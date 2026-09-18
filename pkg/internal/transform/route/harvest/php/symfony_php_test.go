// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractSymfonyPHPConfig(t *testing.T) {
	routes := newRouteSet()
	tokens := lexPHP([]byte(`
        return function (RoutingConfigurator $routes): void {
			$routes->add('status', '/status');
            $routes->add(name: 'users', path: '/users');
			$routes->ADD('health', '/health');
			$routes->add('dynamic', $path);
			$routes->remove('ignored', '/ignored-method');
			$other->add('ignored', '/ignored-variable');
        };

		function qualified(\Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator $qualified) {
			$qualified->add('qualified', '/qualified');
		}
    `))

	extractSymfonyPHPConfig(tokens, routes)

	assert.Equal(t, routeSet{
		"/status":    {},
		"/users":     {},
		"/health":    {},
		"/qualified": {},
	}, routes)
}

func TestSymfonyRoutingConfiguratorVariables(t *testing.T) {
	tokens := lexPHP([]byte(`
		function one(RoutingConfigurator $routes, Other $other) {}
		function two(\Symfony\Component\Routing\Loader\Configurator\ROUTINGCONFIGURATOR $qualified) {}
		RoutingConfigurator::class;
		$before RoutingConfigurator;
	`))

	assert.Equal(t, map[string]struct{}{
		"$routes":    {},
		"$qualified": {},
	}, symfonyRoutingConfiguratorVariables(tokens))
	assert.Empty(t, symfonyRoutingConfiguratorVariables(nil))
}
