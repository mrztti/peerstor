package impl

import (
	"crypto"
	"encoding/hex"
	"strings"

	"go.dedis.ch/cs438/peer"
)

func createChunkHash(chunk []byte) ([]byte, string) {
	h := crypto.SHA256.New()
	h.Write(chunk)
	hash := h.Sum(nil)
	return hash, hex.EncodeToString(hash)
}

func parseMetafile(metafile []byte) []string {
	return strings.Split(string(metafile), peer.MetafileSep)
}
