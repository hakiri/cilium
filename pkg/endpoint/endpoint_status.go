// Copyright 2016-2019 Authors of Cilium
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

package endpoint

import (
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	identitycache "github.com/cilium/cilium/pkg/identity/cache"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

func getEndpointStatusControllers(status *models.EndpointStatus) (controllers cilium_v2.ControllerList) {
	for _, c := range status.Controllers {
		if c.Status == nil {
			continue
		}

		if c.Status.ConsecutiveFailureCount > 0 {
			if controllers == nil {
				controllers = cilium_v2.ControllerList{c}
			} else {
				controllers = append(controllers, c)
			}
		}

		if controllers != nil {
			controllers.Sort()
		}
	}
	return
}

func getEndpointStatusLog(status *models.EndpointStatus) (log []*models.EndpointStatusChange) {
	added := 0
	for _, l := range status.Log {
		if strings.ToLower(l.Code) != models.EndpointStatusChangeCodeOk {
			if log == nil {
				log = []*models.EndpointStatusChange{l}
			} else {
				log = append(log, l)
			}
			added++
			if added > cilium_v2.EndpointStatusLogEntries {
				break
			}
		}
	}
	return
}

func getEndpointIdentity(status *models.EndpointStatus) (identity *cilium_v2.EndpointIdentity) {
	if status.Identity != nil {
		identity = &cilium_v2.EndpointIdentity{
			ID:     status.Identity.ID,
			Labels: status.Identity.Labels,
		}
	}
	return
}

func getEndpointNetworking(status *models.EndpointStatus) (networking *cilium_v2.EndpointNetworking) {
	if status.Networking != nil {
		networking = &cilium_v2.EndpointNetworking{
			Addressing: make(cilium_v2.AddressPairList, len(status.Networking.Addressing)),
		}
		i := 0
		for _, pair := range status.Networking.Addressing {
			networking.Addressing[i] = &cilium_v2.AddressPair{
				IPV4: pair.IPV4,
				IPV6: pair.IPV6,
			}
		}

		networking.Addressing.Sort()
	}
	return
}

func getEndpointPolicy(e *Endpoint) (policy *cilium_v2.EndpointPolicy) {
	if e.desiredPolicy != nil {
		policy = &cilium_v2.EndpointPolicy{
			Ingress: &cilium_v2.EndpointPolicyDirection{
				Enforcing: e.desiredPolicy.IngressPolicyEnabled,
			},
			Egress: &cilium_v2.EndpointPolicyDirection{
				Enforcing: e.desiredPolicy.EgressPolicyEnabled,
			},
		}

		for policyKey := range e.desiredPolicy.PolicyMapState {
			allowedIdentityTuple := cilium_v2.AllowedIdentityTuple{
				DestPort: policyKey.DestPort,
				Protocol: policyKey.Nexthdr,
				Identity: uint64(policyKey.Identity),
			}

			identity := identitycache.LookupIdentityByID(identity.NumericIdentity(policyKey.Identity))
			if identity != nil {
				var l labels.Labels
				if identity.CIDRLabel != nil {
					l = identity.CIDRLabel
				} else {
					l = identity.Labels
				}

				allowedIdentityTuple.IdentityLabels = l.StringMap()
			}

			switch policyKey.TrafficDirection {
			case trafficdirection.Ingress.Uint8():
				if policy.Ingress.Allowed == nil {
					policy.Ingress.Allowed = cilium_v2.AllowedIdentityList{allowedIdentityTuple}
				} else {
					policy.Ingress.Allowed = append(policy.Ingress.Allowed, allowedIdentityTuple)
				}
			case trafficdirection.Egress.Uint8():
				if policy.Egress.Allowed == nil {
					policy.Egress.Allowed = cilium_v2.AllowedIdentityList{allowedIdentityTuple}
				} else {
					policy.Egress.Allowed = append(policy.Egress.Allowed, allowedIdentityTuple)
				}
			}

			if policy.Ingress.Allowed != nil {
				policy.Ingress.Allowed.Sort()
			}

			if policy.Egress.Allowed != nil {
				policy.Egress.Allowed.Sort()
			}
		}
	}

	return
}

func (e *Endpoint) GetCiliumEndpointStatus() *cilium_v2.EndpointStatus {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	model := e.GetModelRLocked()
	modelStatus := model.Status

	controllers := getEndpointStatusControllers(modelStatus)
	identity := getEndpointIdentity(modelStatus)
	log := getEndpointStatusLog(modelStatus)
	networking := getEndpointNetworking(modelStatus)

	return &cilium_v2.EndpointStatus{
		ID:                  int64(e.ID),
		ExternalIdentifiers: modelStatus.ExternalIdentifiers,
		Controllers:         controllers,
		Identity:            identity,
		Log:                 log,
		Networking:          networking,
		Health:              modelStatus.Health,
		State:               string(modelStatus.State),
		Policy:              getEndpointPolicy(e),

		// Scheduled for deprecation in 1.5
		//
		// Status is deprecated but we have some users depending on
		// these fields so they continue to be populated until version
		// 1.5
		Status: cilium_v2.DeprecatedEndpointStatus{
			Controllers: controllers,
			Identity:    identity,
			Log:         log,
			Networking:  networking,
		},
	}
}
