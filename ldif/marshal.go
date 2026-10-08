package ldif

import (
	"encoding/base64"
	"io"
	"strings"
	"strconv"
)

const foldWidth = 76

var itoa = strconv.Itoa

/*
Marshal returns an LDIF string from the given [LDIF].

The default line length is 76 characters. This can be changed by setting
the fw parameter to something else than 0.

For a fold width < 0, no folding will be done, with 0, the default is used.
*/
func Marshal(l *LDIF) (string, error) {
	var (
		err     error
		data    string
		builder strings.Builder
	)

	if err = MarshalStreaming(l, &builder); err == nil {
		data = builder.String()
	}

	return data, err
}

/*
MarshalStreaming returns an error following an attempt to write the return
value of [Marshal] to the input [io.Writer].
*/
func MarshalStreaming(l *LDIF, writer io.Writer) (err error) {
	hasEntry := false
	hasChange := false

	if l.Version > 0 {
		_, err = io.WriteString(writer, "version: 1\n")
	}

	fw := l.FoldWidth
	if fw == 0 {
		fw = foldWidth
	}

	for i := 0; i < len(l.Entries) && err == nil; i++ {
		e := l.Entries[i]
		switch tv := e.(type) {
		case *AddRequest:
			hasChange, err = marshalAddReq(tv, writer, hasEntry, fw)

		case *DelRequest:
			hasChange = true
			if hasEntry {
				return errMixedContent
			}

			_, err = io.WriteString(writer, foldLine("dn: "+tv.DN().String(), fw)+"\n")
			if err == nil {
				_, err = io.WriteString(writer, "changetype: delete\n")
			}

		case *ModifyRequest:
			hasChange, err = marshalModReq(tv, writer, hasEntry, fw)
		case *ModifyDNRequest:
			err = errMDNNotImpl
		case *GenericEntry:
			hasEntry, err = marshalEntry(tv, writer, hasChange, fw)
		}
		_, _ = io.WriteString(writer, "\n")
	}
	return err
}

func marshalEntry(
	tv *GenericEntry,
	writer io.Writer,
	hasChange bool,
	fw int,
) (hasEntry bool, err error) {
	hasEntry = true
	if hasChange {
		err = errMixedContent
		return
	}

	_, err = io.WriteString(writer, foldLine("dn: "+tv.DN().String(), fw)+"\n")
	for k := 0; k < len(tv.Attributes) && err == nil; k++ {
		at := tv.Attributes[k]
		for m := 0; m < len(at.Vals) && err == nil; m++ {
			v := at.Vals[m]
			ev, t := encodeValue(v.String())
			col := ": "
			if t {
				col = ":: "
			}
			_, err = io.WriteString(writer, foldLine(at.Type.String()+col+ev, fw)+"\n")
		}
	}

	return
}

func marshalAddReq(
	tv *AddRequest,
	writer io.Writer,
	hasEntry bool,
	fw int,
) (hasChange bool, err error) {
	hasChange = true
	if hasEntry {
		err = errMixedContent
		return
	}

	_, err = io.WriteString(writer, foldLine("dn: "+tv.DN().String(), fw)+"\n")
	if err == nil {
		_, err = io.WriteString(writer, "changetype: add\n")
		for j := 0; j < len(tv.Attributes) && err == nil; j++ {
			add := tv.Attributes[j]
			typ := add.Type.String()
			if len(add.Vals) == 0 {
				err = errAddValEmpty
				break
			}
			for k := 0; k < len(add.Vals) && err == nil; k++ {
				v := add.Vals[k]
				ev, t := encodeValue(v.String())
				col := ": "
				if t {
					col = ":: "
				}

				_, err = io.WriteString(writer, foldLine(typ+col+ev, fw)+"\n")
			}
		}
	}

	return
}

func marshalModReq(
	tv *ModifyRequest,
	writer io.Writer,
	hasEntry bool,
	fw int,
) (hasChange bool, err error) {
	hasChange = true
	if hasEntry {
		err = errMixedContent
		return
	}

	_, err = io.WriteString(writer, foldLine("dn: "+tv.DN().String(), fw)+"\n")
	if err == nil {
		_, err = io.WriteString(writer, "changetype: modify\n")
	}

	for j := 0; j < len(tv.Changes) && err == nil; j++ {
		mod := tv.Changes[j]
		typ := mod.Modification.Type.String()
		vals := mod.Modification.Vals

		switch mod.Operation {
		case 0:
			err = marshalModReqAddCase(typ, vals, writer, fw)
		case 1:
			err = marshalModReqDelCase(typ, vals, writer, fw)
		case 2:
			err = marshalModReqRepCase(typ, vals, writer, fw)
		default:
			err = errBadModOp
		}
	}

	return
}

func marshalModReqAddCase(typ string, vals []attributeValue, writer io.Writer, fw int) (err error) {
	// add operation - https://tools.ietf.org/html/rfc4511#section-4.6
	if len(vals) == 0 {
		err = errModValEmpty
		return
	}

	_, err = io.WriteString(writer, "add: "+typ+"\n")
	for k := 0; k < len(vals) && err == nil; k++ {
		ev, t := encodeValue(vals[k].String())
		col := ": "
		if t {
			col = ":: "
		}
		_, err = io.WriteString(writer, foldLine(typ+col+ev, fw)+"\n")
	}
	_, _ = io.WriteString(writer, "-\n")

	return
}

func marshalModReqDelCase(typ string, vals []attributeValue, writer io.Writer, fw int) (err error) {
	// delete operation - https://tools.ietf.org/html/rfc4511#section-4.6
	_, err = io.WriteString(writer, "delete: "+typ+"\n")
	for k := 0; k < len(vals) && err == nil; k++ {
		v := vals[k]
		ev, t := encodeValue(v.String())
		if len(ev) == 0 {
			continue // no value means delete 'em all!
		}
		col := ": "
		if t {
			col = ":: "
		}
		_, err = io.WriteString(writer, foldLine(typ+col+ev, fw)+"\n")
	}
	_, _ = io.WriteString(writer, "-\n")

	return
}

func marshalModReqRepCase(typ string, vals []attributeValue, writer io.Writer, fw int) (err error) {
	// replace operation - https://tools.ietf.org/html/rfc4511#section-4.6
	if len(vals) == 0 {
		err = errModValEmpty
		return
	}

	_, err = io.WriteString(writer, "replace: "+typ+"\n")
	for k := 0; k < len(vals) && err == nil; k++ {
		v := vals[k]
		ev, t := encodeValue(v.String())
		col := ": "
		if t {
			col = ":: "
		}
		_, err = io.WriteString(writer, foldLine(typ+col+ev, fw)+"\n")
	}
	_, _ = io.WriteString(writer, "-\n")

	return
}

func encodeValue(value string) (string, bool) {
	if value == "" {
		return value, false
	}

	required := false
	switch value[0] {
	// SAFE-INIT-CHAR (RFC 2849): a value MUST be base64 encoded when it
	// begins with SPACE, ':' or '<', otherwise it cannot be read back.
	case ' ', ':', '<':
		required = true
	}
	// A value that ends in SPACE SHOULD be base64 encoded (RFC 2849 note 8).
	if value[len(value)-1] == ' ' {
		required = true
	}
	if !required {
		for _, r := range value {
			if r < ' ' || r > '~' { // not a printable ASCII SAFE-CHAR
				required = true
				break
			}
		}
	}

	if !required {
		return value, false
	}
	return base64.StdEncoding.EncodeToString([]byte(value)), true
}

func foldLine(line string, fw int) (folded string) {
	if fw < 0 {
		return line
	}
	if len(line) <= fw {
		return line
	}

	folded = line[:fw] + "\n"
	line = line[fw:]

	for len(line) > fw-1 {
		folded += " " + line[:fw-1] + "\n"
		line = line[fw-1:]
	}

	if len(line) > 0 {
		folded += " " + line
	}
	return
}

/*
Dump writes the given entries to the [io.Writer].

The entries argument will contain a series of [Entry] type implementation
instances.

See the [Marshal] package-level function for information regarding the
foldWidth (fw) argument.
*/
func Dump(fh io.Writer, fw int, entries ...any) error {
	l, err := ToLDIF(entries...)
	if err == nil {
		l.FoldWidth = fw
		err = MarshalStreaming(l, fh)
	}
	return err
}

/*
ToLDIF returns an instance of *[LDIF] alongside an error following an
attempt to incorporate the input entries variadic argument(s) into the
return value.

The input value(s) type must be [Entry] or [][Entry].
*/
func ToLDIF(entries ...any) (*LDIF, error) {
	l := &LDIF{}
	var err error
	for i := 0; i < len(entries) && err == nil; i++ {
		switch tv := entries[i].(type) {
		case []Entry:
			for _, en := range tv {
				l.Entries = append(l.Entries, en)
			}

		case Entry:
			l.Entries = append(l.Entries, tv)

		default:
			err = generalError("ToLDIF: unsupported type at slice index ",
				itoa(i), "; must be Entry or []Entry")
		}
	}
	return l, err
}
