// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// +build linux

package route

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"

	"github.com/vishvananda/netlink"
)

const (
	// RouteReplaceMaxTries is the number of attempts the route will be
	// attempted to be added or updated in case the kernel returns an error
	RouteReplaceMaxTries = 10

	// RouteReplaceRetryInterval is the interval in which
	// RouteReplaceMaxTries attempts are attempted
	RouteReplaceRetryInterval = 100 * time.Millisecond
)

// getNetlinkRoute returns the route configuration as netlink.Route
func (r *Route) getNetlinkRoute() netlink.Route {
	rt := netlink.Route{
		Dst: &r.Prefix,
		Src: r.Local,
		MTU: r.MTU,
	}

	if r.Nexthop != nil {
		rt.Gw = *r.Nexthop
	}

	if r.Scope != 0 {
		rt.Scope = r.Scope
	}

	return rt
}

// getNexthopAsIPNet returns the nexthop of the route as IPNet
func (r *Route) getNexthopAsIPNet() *net.IPNet {
	if r.Nexthop == nil {
		return nil
	}

	if r.Nexthop.To4() != nil {
		return &net.IPNet{IP: *r.Nexthop, Mask: net.CIDRMask(32, 32)}
	}

	return &net.IPNet{IP: *r.Nexthop, Mask: net.CIDRMask(128, 128)}
}

// ToIPCommand converts the route into a full "ip route ..." command
func (r *Route) ToIPCommand(dev string) []string {
	res := []string{"ip"}
	if r.Prefix.IP.To4() == nil {
		res = append(res, "-6")
	}
	res = append(res, "route", "add", r.Prefix.String())
	if r.Nexthop != nil {
		res = append(res, "via", r.Nexthop.String())
	}
	if r.MTU != 0 {
		res = append(res, "mtu", fmt.Sprintf("%d", r.MTU))
	}
	res = append(res, "dev", dev)
	return res
}

func ipFamily(ip net.IP) int {
	if ip.To4() == nil {
		return netlink.FAMILY_V6
	}

	return netlink.FAMILY_V4
}

// Lookup attempts to find the linux route based on the route specification.
// If the route exists, the route is returned, otherwise an error is returned.
func Lookup(route Route) (*Route, error) {
	link, err := netlink.LinkByName(route.Device)
	if err != nil {
		return nil, fmt.Errorf("unable to find interface '%s' of route: %s", route.Device, err)
	}

	routeSpec := route.getNetlinkRoute()

	nlRoute := lookup(link, &routeSpec)
	if nlRoute == nil {
		return nil, nil
	}

	result := &Route{
		Local:   nlRoute.Src,
		Device:  link.Attrs().Name,
		MTU:     nlRoute.MTU,
		Scope:   nlRoute.Scope,
		Nexthop: &nlRoute.Gw,
	}

	if nlRoute.Dst != nil {
		result.Prefix = *nlRoute.Dst
	}

	return result, nil
}

// lookup finds a particular route as specified by the filter which points
// to the specified device. The filter route can have the following fields set:
//  - Dst
//  - LinkIndex
//  - Scope
//  - Gw
func lookup(link netlink.Link, route *netlink.Route) *netlink.Route {
	routes, err := netlink.RouteList(link, ipFamily(route.Dst.IP))
	if err != nil {
		return nil
	}

	for _, r := range routes {
		if r.Dst != nil && route.Dst == nil {
			continue
		}

		if route.Dst != nil && r.Dst == nil {
			continue
		}

		aMaskLen, aMaskBits := r.Dst.Mask.Size()
		bMaskLen, bMaskBits := route.Dst.Mask.Size()
		if r.Scope == route.Scope &&
			aMaskLen == bMaskLen && aMaskBits == bMaskBits &&
			r.Dst.IP.Equal(route.Dst.IP) && r.Gw.Equal(route.Gw) {
			return &r
		}
	}

	return nil
}

func createNexthopRoute(link netlink.Link, routerNet *net.IPNet) *netlink.Route {
	// This is the L2 route which makes router IP available behind the
	// interface.
	rt := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       routerNet,
	}

	// Known issue: scope for IPv6 routes is not propagated correctly. If
	// we set the scope here, lookup() will be unable to identify the route
	// again and we will continously re-add the route
	if routerNet.IP.To4() != nil {
		rt.Scope = netlink.SCOPE_LINK
	}

	return rt
}

// replaceNexthopRoute verifies that the L2 route for the router IP which is
// used as nexthop for all node routes is properly installed. If unavailable or
// incorrect, it will be replaced with the proper L2 route.
func replaceNexthopRoute(link netlink.Link, routerNet *net.IPNet) (bool, error) {
	route := createNexthopRoute(link, routerNet)
	if lookup(link, route) == nil {
		scopedLog := log.WithField(logfields.Route, route)

		if err := netlink.RouteReplace(route); err != nil {
			scopedLog.WithError(err).Error("Unable to add L2 nexthop route")
			return false, fmt.Errorf("unable to add L2 nexthop route: %s", err)
		}

		scopedLog.Info("Added L2 nexthop route")
		return true, nil
	}

	return false, nil
}

// deleteNexthopRoute deletes
func deleteNexthopRoute(link netlink.Link, routerNet *net.IPNet) error {
	route := createNexthopRoute(link, routerNet)
	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("unable to delete L2 nexthop route: %s", err)
	}

	return nil
}

func replaceRoute(route Route, mtuConfig mtu.Configuration) (bool, error) {
	var nexthopRouteCreated bool

	link, err := netlink.LinkByName(route.Device)
	if err != nil {
		return false, fmt.Errorf("unable to lookup interface %s: %s", route.Device, err)
	}

	routerNet := route.getNexthopAsIPNet()
	if routerNet != nil {
		if _, err := replaceNexthopRoute(link, routerNet); err != nil {
			return false, fmt.Errorf("unable to add nexthop route: %s", err)
		}

		nexthopRouteCreated = true
	}

	routeSpec := route.getNetlinkRoute()
	routeSpec.LinkIndex = link.Attrs().Index

	if routeSpec.MTU != 0 {
		// If the route includes the local address, then the route is for
		// local containers and we can use a high MTU for transmit. Otherwise,
		// it needs to be able to fit within the MTU of tunnel devices.
		if route.Prefix.Contains(route.Local) {
			routeSpec.MTU = mtuConfig.GetDeviceMTU()
		} else {
			routeSpec.MTU = mtuConfig.GetRouteMTU()
		}
	}

	if lookup(link, &routeSpec) == nil {
		err := fmt.Errorf("routeReplace not called yet")

		// Workaround: See description of this function
		for i := 0; err != nil && i < RouteReplaceMaxTries; i++ {
			err = netlink.RouteReplace(&routeSpec)
			if err == nil {
				break
			}
			time.Sleep(RouteReplaceRetryInterval)
		}

		if err != nil {
			if nexthopRouteCreated {
				deleteNexthopRoute(link, routerNet)
			}
			return false, err
		}

		return true, nil
	}

	return false, nil
}

// ReplaceRoute adds or updates a Linux kernel route. The route described can be in
// the following two forms:
//
// direct:
//   prefix dev foo
//
// nexthop:
//   prefix via nexthop dev foo
//
// If a nexthop route is specified, this function will check whether a direct
// route to the nexthop exists and add if required. This means that the
// following two routes will exist afterwards:
//
//   nexthop dev foo
//   prefix via nexthop dev foo
//
// Due to a bug in the Linux kernel, the prefix route is attempted to be
// updated RouteReplaceMaxTries with an interval of RouteReplaceRetryInterval.
// This is a workaround for a race condition in which the direct route to the
// nexthop is not available immediately and the prefix route can fail with
// EINVAL if the Netlink calls are issued in short order.
//
// An error is returned if the route can not be added or updated.
func ReplaceRoute(route Route, mtuConfig mtu.Configuration) error {
	replaced, err := replaceRoute(route, mtuConfig)
	if err != nil {
		route.getLogger().WithError(err).Error("Unable to add route")
		return err
	} else if replaced {
		route.getLogger().Info("Updated route")
	}

	return nil
}

func deleteRoute(route Route) error {
	link, err := netlink.LinkByName(route.Device)
	if err != nil {
		return fmt.Errorf("unable to lookup interface %s: %s", route.Device, err)
	}

	// Deletion of routes with Nexthop or Local set fails for IPv6.
	// Therefore do not use getNetlinkRoute().
	routeSpec := netlink.Route{
		Dst:       &route.Prefix,
		LinkIndex: link.Attrs().Index,
	}

	// Scope can only be specified for IPv4
	if route.Prefix.IP.To4() != nil {
		routeSpec.Scope = route.Scope
	}

	if err := netlink.RouteDel(&routeSpec); err != nil {
		return err
	}

	return nil
}

// DeleteRoute removes a route
func DeleteRoute(route Route) error {
	if err := deleteRoute(route); err != nil {
		route.getLogger().WithError(err).Error("Unable to delete route")
		return err
	} else {
		route.getLogger().Info("Deleted route")
	}

	return nil
}
