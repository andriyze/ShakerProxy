package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/vpn"
)

type vpnFirewallFamily struct {
	ipv6    bool
	command string
	restore string
}

var (
	vpnFirewallIPv4 = vpnFirewallFamily{command: iptablesBinary, restore: iptablesRestoreBinary}
	vpnFirewallIPv6 = vpnFirewallFamily{ipv6: true, command: ip6tablesBinary, restore: ip6tablesRestoreBinary}
)

var vpnChainsByTable = map[string][]string{
	"filter": {vpn.ForwardChain, vpn.InputChain},
	"nat":    {vpn.PostroutingChain},
}

func (m *VPNManager) families() []vpnFirewallFamily {
	if m.ipv6Available() {
		return []vpnFirewallFamily{vpnFirewallIPv4, vpnFirewallIPv6}
	}
	return []vpnFirewallFamily{vpnFirewallIPv4}
}

// applyFirewallLocked loads the VPN chains for every family and hooks them
// in. An IPv6 failure fails the whole change: VPN devices would otherwise
// reach ShakerProxy's own services over IPv6.
func (m *VPNManager) applyFirewallLocked(ctx context.Context, state vpn.State) error {
	if m.Runner == nil {
		return errors.New("the firewall command runner is unavailable")
	}
	lock, err := m.coordinate(ctx)
	if err != nil {
		return err
	}
	defer lock.Release()
	for _, family := range m.families() {
		rules, err := vpn.RenderFirewall(state, family.ipv6)
		if err != nil {
			return err
		}
		if err := m.restoreChains(ctx, family, "filter", rules.Filter); err != nil {
			return fmt.Errorf("load the VPN firewall: %w", err)
		}
		if err := m.restoreChains(ctx, family, "nat", rules.NAT); err != nil {
			return fmt.Errorf("load the VPN NAT rules: %w", err)
		}
		if err := m.ensureJump(ctx, family.command, "filter", "INPUT", vpn.InputChain); err != nil {
			return err
		}
		parent := m.forwardParent(ctx, family)
		if err := m.placeBelow(ctx, family.command, parent, vpn.ForwardChain, securityForwardChain); err != nil {
			return err
		}
		other := "DOCKER-USER"
		if parent == "DOCKER-USER" {
			other = "FORWARD"
		}
		if err := m.removeJumps(ctx, family.command, "filter", other, vpn.ForwardChain); err != nil {
			return err
		}
		if err := m.ensureJump(ctx, family.command, "nat", "POSTROUTING", vpn.PostroutingChain); err != nil {
			return err
		}
	}
	return nil
}

// removeFirewallLocked detaches and deletes the VPN chains.
func (m *VPNManager) removeFirewallLocked(ctx context.Context) error {
	if m.Runner == nil {
		return nil
	}
	lock, err := m.coordinate(ctx)
	if err != nil {
		return err
	}
	defer lock.Release()
	var problems []error
	for _, family := range m.families() {
		for _, hook := range []struct{ table, parent, chain string }{
			{"filter", "INPUT", vpn.InputChain},
			{"filter", "DOCKER-USER", vpn.ForwardChain},
			{"filter", "FORWARD", vpn.ForwardChain},
			{"nat", "POSTROUTING", vpn.PostroutingChain},
		} {
			if hook.parent == "DOCKER-USER" && !m.chainExists(ctx, family.command, "filter", "DOCKER-USER") {
				continue
			}
			if err := m.removeJumps(ctx, family.command, hook.table, hook.parent, hook.chain); err != nil {
				problems = append(problems, err)
			}
		}
		for table, chains := range vpnChainsByTable {
			for _, chain := range chains {
				if !m.chainExists(ctx, family.command, table, chain) {
					continue
				}
				arguments := tableArguments(table)
				if _, err := m.Runner.Run(ctx, family.command, append(append([]string{}, arguments...), "-F", chain), nil); err != nil {
					problems = append(problems, err)
					continue
				}
				if _, err := m.Runner.Run(ctx, family.command, append(append([]string{}, arguments...), "-X", chain), nil); err != nil {
					problems = append(problems, err)
				}
			}
		}
	}
	m.installed = nil
	return errors.Join(problems...)
}

// forwardParent is where the VPN forward chain hangs: DOCKER-USER when
// Docker manages the family (Docker's FORWARD policy drops), else FORWARD.
// The traffic policy's security chain hangs in the same place.
func (m *VPNManager) forwardParent(ctx context.Context, family vpnFirewallFamily) string {
	if m.chainExists(ctx, family.command, "filter", "DOCKER-USER") {
		return "DOCKER-USER"
	}
	return "FORWARD"
}

// restoreChains loads a table's VPN batch unless that batch is installed
// and the chains still list as they did right after it.
func (m *VPNManager) restoreChains(ctx context.Context, family vpnFirewallFamily, table, batch string) error {
	key := family.restore + " " + table
	listing, listed := m.listChains(ctx, family, table)
	if installed, ok := m.installed[key]; ok && listed && installed.batch == batch && installed.listing == listing {
		return nil
	}
	if _, err := m.Runner.Run(ctx, family.restore, []string{"--noflush"}, []byte(batch)); err != nil {
		return err
	}
	if m.installed == nil {
		m.installed = map[string]installedSecurityBatch{}
	}
	if listing, listed = m.listChains(ctx, family, table); listed {
		m.installed[key] = installedSecurityBatch{batch: batch, listing: listing}
	} else {
		delete(m.installed, key)
	}
	return nil
}

func (m *VPNManager) listChains(ctx context.Context, family vpnFirewallFamily, table string) (string, bool) {
	var listing strings.Builder
	for _, chain := range vpnChainsByTable[table] {
		output, err := m.Runner.Run(ctx, family.command, append(tableArguments(table), "-S", chain), nil)
		if err != nil {
			return "", false
		}
		listing.Write(output)
		listing.WriteByte('\n')
	}
	return listing.String(), true
}

// ensureJump inserts "-j chain" at the top of parent unless it is there.
func (m *VPNManager) ensureJump(ctx context.Context, command, table, parent, chain string) error {
	arguments := tableArguments(table)
	if _, err := m.Runner.Run(ctx, command, append(append([]string{}, arguments...), "-C", parent, "-j", chain), nil); err == nil {
		return nil
	}
	if _, err := m.Runner.Run(ctx, command, append(append([]string{}, arguments...), "-I", parent, "1", "-j", chain), nil); err != nil {
		return fmt.Errorf("hook %s into %s: %w", chain, parent, err)
	}
	return nil
}

// placeBelow keeps "-j chain" in the filter parent directly below the
// traffic policy's security hook (or first when there is none), so its
// blocks see VPN traffic before the VPN chain accepts it. The traffic
// policy always inserts its hook first, which keeps this order.
func (m *VPNManager) placeBelow(ctx context.Context, command, parent, chain, above string) error {
	listing, err := m.Runner.Run(ctx, command, []string{"-w", "5", "-S", parent}, nil)
	if err != nil {
		return fmt.Errorf("list %s: %w", parent, err)
	}
	ours, theirs := hookPosition(string(listing), parent, chain), hookPosition(string(listing), parent, above)
	if ours != 0 && (theirs == 0 || ours > theirs) {
		return nil
	}
	if ours != 0 {
		if err := m.removeJumps(ctx, command, "filter", parent, chain); err != nil {
			return err
		}
		if listing, err = m.Runner.Run(ctx, command, []string{"-w", "5", "-S", parent}, nil); err != nil {
			return fmt.Errorf("list %s: %w", parent, err)
		}
		theirs = hookPosition(string(listing), parent, above)
	}
	position := theirs + 1
	if _, err := m.Runner.Run(ctx, command, []string{"-w", "5", "-I", parent, fmt.Sprint(position), "-j", chain}, nil); err != nil {
		return fmt.Errorf("hook %s into %s: %w", chain, parent, err)
	}
	return nil
}

func (m *VPNManager) removeJumps(ctx context.Context, command, table, parent, chain string) error {
	arguments := tableArguments(table)
	check := append(append([]string{}, arguments...), "-C", parent, "-j", chain)
	for removed := 0; ; removed++ {
		if _, err := m.Runner.Run(ctx, command, check, nil); err != nil {
			return nil
		}
		if removed >= 64 {
			return fmt.Errorf("%s holds too many jumps to %s", parent, chain)
		}
		if _, err := m.Runner.Run(ctx, command, append(append([]string{}, arguments...), "-D", parent, "-j", chain), nil); err != nil {
			return err
		}
	}
}

func (m *VPNManager) chainExists(ctx context.Context, command, table, chain string) bool {
	_, err := m.Runner.Run(ctx, command, append(tableArguments(table), "-n", "-L", chain), nil)
	return err == nil
}

func tableArguments(table string) []string {
	if table == "filter" {
		return []string{"-w", "5"}
	}
	return []string{"-w", "5", "-t", table}
}
