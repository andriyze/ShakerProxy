package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

// captureImportResponse is returned once an uploaded capture is analyzed-ready.
type captureImportResponse struct {
	capture.ImportResult
	// ViewPath links to the Traffic view scoped to this import.
	ViewPath string `json:"view_path"`
}

// importCapture streams an uploaded .pcapng to the gateway in bounded chunks,
// which stores it as a finalized capture the offline analyzers process. The
// upload is multipart/form-data with a "file" part and optional "name" and
// "description" fields, before or after the file.
func (s *Server) importCapture(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		writeError(w, http.StatusUnsupportedMediaType, "import_not_multipart", "upload the capture as multipart/form-data with a 'file' part")
		return
	}
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "import_unreadable", "the upload could not be read")
		return
	}

	name, description, fileName := "", "", ""
	username := sessionUsername(r.Context())
	for {
		part, partErr := reader.NextPart()
		if errors.Is(partErr, io.EOF) {
			break
		}
		if partErr != nil {
			writeError(w, http.StatusBadRequest, "import_unreadable", "the upload could not be read")
			return
		}
		switch part.FormName() {
		case "name":
			name = readFormField(part)
		case "description":
			description = readFormField(part)
		case "file":
			fileName = part.FileName()
			// Fields after the file are read once it has been streamed, and
			// sent with the last chunk.
			trailing := func() (string, string, error) {
				lateName, lateDescription, err := readTrailingFields(reader)
				if err != nil {
					return "", "", err
				}
				if lateName != "" {
					lateName = importName(lateName, fileName)
				}
				if lateDescription != "" {
					lateDescription = importDescription(lateDescription, fileName)
				}
				return lateName, lateDescription, nil
			}
			s.streamCaptureImport(w, r, part, importName(name, fileName), importDescription(description, fileName), username, trailing)
			return
		default:
			part.Close()
		}
	}
	writeError(w, http.StatusBadRequest, "import_file_missing", "the upload has no 'file' part")
}

// readTrailingFields reads the parts after the file: a name or description
// field there still names the capture. A second file part is refused.
func readTrailingFields(reader *multipart.Reader) (string, string, error) {
	name, description := "", ""
	for parts := 0; ; parts++ {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return name, description, nil
		}
		if err != nil || parts >= 16 {
			return "", "", errors.New("the upload could not be read")
		}
		switch part.FormName() {
		case "name":
			name = readFormField(part)
		case "description":
			description = readFormField(part)
		case "file":
			part.Close()
			return "", "", errors.New("the upload has more than one 'file' part")
		default:
			part.Close()
		}
	}
}

func (s *Server) streamCaptureImport(w http.ResponseWriter, r *http.Request, file io.Reader, name, description, username string, trailing func() (string, string, error)) {
	limited := io.LimitReader(file, capture.DefaultMaxImportBytes+1)
	var begun gatewayprotocol.BeginCaptureImportResult
	beginParams := gatewayprotocol.BeginCaptureImportParams{Name: name, Description: description, Administrator: username}
	if err := s.gateway.Call(r.Context(), "BeginCaptureImport", beginParams, &begun); err != nil {
		writeError(w, http.StatusConflict, "import_rejected", err.Error())
		return
	}
	sessionID := begun.SessionID

	offset := int64(0)
	buffer := make([]byte, capture.ImportChunkBytes)
	var result capture.ImportResult
	for {
		read, readErr := io.ReadFull(limited, buffer)
		atEnd := errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF)
		if readErr != nil && !atEnd {
			s.abortImport(r, sessionID)
			writeError(w, http.StatusBadRequest, "import_unreadable", "the upload could not be read")
			return
		}
		if offset+int64(read) > capture.DefaultMaxImportBytes {
			s.abortImport(r, sessionID)
			writeError(w, http.StatusRequestEntityTooLarge, "import_too_large", fmt.Sprintf("the capture exceeds the %d MiB import limit", capture.DefaultMaxImportBytes>>20))
			return
		}
		// A full chunk with no error may still be the exact end; the next read
		// then returns EOF with no data and carries the eof marker.
		eof := atEnd
		var appended gatewayprotocol.AppendCaptureImportResult
		params := gatewayprotocol.AppendCaptureImportParams{SessionID: sessionID, Offset: offset, Data: buffer[:read], EOF: eof}
		if eof && trailing != nil {
			lateName, lateDescription, err := trailing()
			if err != nil {
				s.abortImport(r, sessionID)
				writeError(w, http.StatusBadRequest, "import_unreadable", err.Error())
				return
			}
			params.Name, params.Description = lateName, lateDescription
		}
		if err := s.gateway.Call(r.Context(), "AppendCaptureImport", params, &appended); err != nil {
			s.abortImport(r, sessionID)
			writeError(w, http.StatusBadRequest, "import_rejected", err.Error())
			return
		}
		offset += int64(read)
		if eof {
			if appended.Result != nil {
				result = *appended.Result
			}
			break
		}
	}

	s.logger.Info("capture import accepted", "username", username, "capture_id", result.SessionID, "packets", result.Packets, "bytes", result.SizeBytes, "truncated_bytes", result.TruncatedBytes)
	writeJSON(w, http.StatusCreated, captureImportResponse{ImportResult: result, ViewPath: "/#/traffic?capture_session_id=" + result.SessionID})
}

// abortImport drops the in-progress import and its temporary file on the
// gateway. It runs even when the request was cancelled (the browser gave up
// mid-upload), so it does not use the request's context; failure here only
// means the import is already gone, and the gateway expires it regardless.
func (s *Server) abortImport(r *http.Request, sessionID string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := s.gateway.Call(ctx, "AbortCaptureImport", gatewayprotocol.AbortCaptureImportParams{SessionID: sessionID}, nil); err != nil {
		s.logger.Warn("capture import could not be aborted; it expires on its own", "session_id", sessionID, "error", err)
	}
}

func readFormField(part io.ReadCloser) string {
	defer part.Close()
	value, err := io.ReadAll(io.LimitReader(part, 1<<20))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(value))
}

func importName(name, fileName string) string {
	if name != "" {
		return truncateField(name, 96)
	}
	if base := cleanFileName(fileName); base != "" {
		return truncateField(base, 96)
	}
	return "Imported capture"
}

func importDescription(description, fileName string) string {
	if description != "" {
		return truncateField(description, 1024)
	}
	if base := cleanFileName(fileName); base != "" {
		return truncateField("Imported from "+base, 1024)
	}
	return ""
}

// cleanFileName keeps only a readable base name for display; it never reaches
// the filesystem (the gateway generates the session ID).
func cleanFileName(name string) string {
	name = strings.TrimSpace(name)
	if slash := strings.LastIndexAny(name, `/\`); slash >= 0 {
		name = name[slash+1:]
	}
	var builder strings.Builder
	for _, char := range name {
		if char < 0x20 || char == 0x7f {
			continue
		}
		builder.WriteRune(char)
	}
	return strings.TrimSpace(builder.String())
}

func truncateField(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return strings.TrimSpace(value[:max])
}
