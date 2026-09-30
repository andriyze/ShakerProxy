package daemon

import (
	"context"
	"errors"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

// radvdFinalizer is implemented by the confirmation finalizer when it can
// also control shakerproxy-radvd (networkapply.OSNetworkServices in production).
type radvdFinalizer interface {
	EnableRadvd(context.Context) error
	DisableRadvd(context.Context) error
}

// finalizeRadvd mirrors the DHCPv4 finalizer: router advertisements are
// enabled for boot only after confirmation, and kept off otherwise. A plan
// that routes IPv6 fails closed when the finalizer cannot manage radvd.
func finalizeRadvd(ctx context.Context, finalizer confirmationFinalizer, plan networkplan.Plan) error {
	services, ok := finalizer.(radvdFinalizer)
	if !ok {
		if networkplan.RoutesIPv6(plan) {
			return errors.New("router advertisement boot enablement is unavailable")
		}
		return nil
	}
	if networkplan.RoutesIPv6(plan) {
		return services.EnableRadvd(ctx)
	}
	return services.DisableRadvd(ctx)
}
