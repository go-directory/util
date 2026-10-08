package ldif

import (
	"github.com/go-directory/common"
)

func parserError(msg ...string) error {
        m := append([]string{"LDIF parse error: "}, msg...)
        return common.ErrorParse.New(m...)
}

func generalError(msg ...string) error {
        m := append([]string{"LDIF general error: "}, msg...)
        return common.ErrorGeneral.New(m...)
}

// pre-crafted errors
var (
	errMixedContent = generalError("cannot mix change records and content records")
	errMDNNotImpl = generalError("ModifyDN not yet implemented")
	errAddValEmpty = parserError("changetype 'add' requires non empty value list")
	errModValEmpty = parserError("changetype 'modify' requires non empty value list")
	errBadModOp = parserError("invalid change op in modify request; want add(0), delete(1), replace(2)")

	// not sure if we need this
        errBadEntryType = generalError("MarshalStreaming: unexpected Entries slice type; must be pointer to Entry impl. type")
)
