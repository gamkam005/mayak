//go:build !lite

package asn

import _ "embed"

//go:embed ip2asn-v4.bin.gz
var blob []byte
