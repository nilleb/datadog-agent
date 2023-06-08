//go:build windows

package winregistry

import (
	"errors"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"golang.org/x/sys/windows/registry"
	"gopkg.in/yaml.v2"
	"io/fs"
	"strings"
)

const (
	checkName = "windows_registry"
)

type metricCfg struct {
	Name           string
	Mappings       []map[string]float64   `yaml:"mapping"`
	ValueIfMissing util.Optional[float64] `yaml:"omitempty"`
}

type registryKeyCfg struct {
	Name    string
	Metrics map[string]metricCfg
}

type checkCfg struct {
	RegistryKeys map[string]registryKeyCfg `yaml:"registry_keys"`
}

// registryKey is the in-memory representation of the key to monitor
// it's different from the regstryKeyCfg because we need to split the hive
// from the keypath. It's easier to do this once during the Configure phase,
// than every time the check runs.
type registryKey struct {
	name            string
	hive            registry.Key
	keyPath         string
	originalKeyPath string // keep the original keypath around, for logging errors
	metrics         map[string]metricCfg
}

// WindowsRegistryCheck contains the field for the WindowsRegistryCheck
type WindowsRegistryCheck struct {
	core.CheckBase
	metrics.Gauge
	registryKeys []registryKey
}

func (c *WindowsRegistryCheck) Configure(integrationConfigDigest uint64, data integration.Data, initConfig integration.Data, source string) error {
	err := c.CommonConfigure(integrationConfigDigest, initConfig, data, source)
	if err != nil {
		return err
	}

	var conf checkCfg
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return err
	}

	c.registryKeys = make([]registryKey, len(conf.RegistryKeys))

	hiveMap := map[string]registry.Key{
		"HKLM":               registry.LOCAL_MACHINE,
		"HKEY_LOCAL_MACHINE": registry.LOCAL_MACHINE,
		"HKU":                registry.USERS,
		"HKEY_USERS":         registry.USERS,
		"HKEY_CLASSES_ROOT":  registry.CLASSES_ROOT,
		"HKCR":               registry.CLASSES_ROOT,
	}

	for regKey, regKeyConfig := range conf.RegistryKeys {
		splitKeypath := strings.Split(regKey, "\\")
		if len(splitKeypath) < 2 {
			return log.Errorf("the key %s is too short to be a valid key", regKey)
		}

		if hive, found := hiveMap[splitKeypath[0]]; found {
			c.registryKeys = append(c.registryKeys, registryKey{
				name:            regKeyConfig.Name,
				hive:            hive,
				originalKeyPath: regKey,
				keyPath:         strings.Join(splitKeypath[1:], "\\"),
				metrics:         regKeyConfig.Metrics,
			})
		} else {
			return log.Errorf("unknown hive %s", splitKeypath[0])
		}
	}

	return nil
}

func (c *WindowsRegistryCheck) Run() error {
	sender, err := c.GetSender()
	if err != nil {
		return err
	}

	for _, regKey := range c.registryKeys {
		k, err := registry.OpenKey(regKey.hive, regKey.keyPath, registry.QUERY_VALUE)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				// Treat access denied as errors
				log.Errorf("access denied while accessing key %s: %s", regKey.originalKeyPath, err)
			} else if errors.Is(err, registry.ErrNotExist) {
				log.Warnf("key %s was not found: %s", regKey.originalKeyPath, err)?
			}
		} else {
			for valueName, metric := range regKey.metrics {
				_, valueType, err := k.GetValue(valueName, nil)
				// err will never be nil, because we pass a buffer that is too small
				if errors.Is(err, registry.ErrNotExist) {
					if valueIfMissing, found := metric.ValueIfMissing.Get(); found {
						sender.Gauge(fmt.Sprintf("windows.registry.%s.%s", regKey.name, metric.Name), valueIfMissing, "", nil)
					} else {
						log.Warnf("value %s of key %s was not found: %s", valueName, regKey.name, err)
					}
				} else if errors.Is(err, fs.ErrPermission) {
					log.Errorf("access denied while accessing value %s of key %s: %s", valueName, regKey.originalKeyPath, err)
				} else if errors.Is(err, registry.ErrShortBuffer) {
					// This is expected, but now we have the value type
					switch valueType {
					case registry.DWORD:
						fallthrough
					case registry.QWORD:
						val, _, err := k.GetIntegerValue(valueName)
						if err != nil {
							log.Errorf("error accessing value %s of key %s: %s", valueName, regKey.originalKeyPath, err)
							continue
						}
						sender.Gauge(fmt.Sprintf("windows.registry.%s.%s", regKey.name, metric.Name), float64(val), "", nil)
						break
					case registry.SZ:
						fallthrough
					case registry.EXPAND_SZ: // Should we expand the references to environment variables ?
						val, _, err := k.GetStringValue(valueName)
						if err != nil {
							log.Errorf("error accessing value %s of key %s: %s", valueName, regKey.originalKeyPath, err)
							continue
						}
						mappingFound := false
						for _, mapping := range metric.Mappings {
							if mappedValue, found := mapping[val]; found {
								sender.Gauge(fmt.Sprintf("windows.registry.%s.%s", regKey.name, metric.Name), mappedValue, "", nil)
								// Stop at first mapping found
								mappingFound = true
								break
							}
						}
						if !mappingFound {
							log.Warnf("no mapping found for value %s of key %s", valueName, regKey.originalKeyPath)
						}
					default:
						log.Warnf("unsupported data type of value %s for key %s: %s", valueName, regKey.originalKeyPath, valueType)
					}
				}
			}
		}
	}
	return nil
}

func windowsRegistryCheckFactory() check.Check {
	return &WindowsRegistryCheck{
		CheckBase: core.NewCheckBase(checkName),
	}
}

func init() {
	core.RegisterCheck(checkName, windowsRegistryCheckFactory)
}
