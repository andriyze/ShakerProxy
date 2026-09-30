// Short installer URL, e.g. `curl -fsSL https://install.<domain> | sh`.
//
// Serves install/index.sh from the latest published release's immutable tag,
// never from `main`, so merging to main is not a production deploy of the
// installer. index.sh itself changes nothing: it hands over to the release's
// bootstrap, which verifies the signed manifest against the pinned key.
const REPOSITORY = 'andriyze/ShakerProxy'
const TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$/
const FETCH_HEADERS = { 'User-Agent': 'shakerproxy-install-worker' }

function failure(message) {
  return new Response(`echo "${message}" >&2; exit 1\n`, {
    status: 502,
    headers: {
      'Content-Type': 'text/x-shellscript; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  })
}

// GitHub answers /releases/latest with a redirect to the newest non-draft,
// non-prerelease tag; this avoids the rate-limited REST API.
async function latestReleaseTag() {
  const response = await fetch(`https://github.com/${REPOSITORY}/releases/latest`, {
    headers: FETCH_HEADERS,
    redirect: 'manual',
    cf: { cacheTtl: 300, cacheEverything: true },
  })
  const location = response.headers.get('Location') || ''
  const tag = decodeURIComponent(location.split('/releases/tag/')[1] || '')
  return TAG_PATTERN.test(tag) ? tag : null
}

export default {
  async fetch() {
    const tag = await latestReleaseTag()
    if (!tag) {
      return failure('No stable ShakerProxy release is published yet.')
    }
    const upstream = await fetch(`https://raw.githubusercontent.com/${REPOSITORY}/${tag}/install/index.sh`, {
      headers: FETCH_HEADERS,
      cf: { cacheTtl: 300, cacheEverything: true },
    })
    if (!upstream.ok) {
      return failure('Could not load the ShakerProxy installer. Try again in a minute.')
    }
    return new Response(upstream.body, {
      status: 200,
      headers: {
        'Content-Type': 'text/x-shellscript; charset=utf-8',
        'Cache-Control': 'public, max-age=300',
        'X-Content-Type-Options': 'nosniff',
        'X-ShakerProxy-Release': tag,
      },
    })
  },
}
