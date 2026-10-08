package ldif

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"iter"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-directory/protocol"
	"github.com/go-directory/syntax"
)

type (
	attributeList  = protocol.AttributeList
	attributeDesc  = protocol.AttributeDescription
	attributeValue = protocol.AttributeValue
)

/*
[go-directory/protocol] type alias.

[go-directory/protocol]: https://github.com/go-directory/syntax
*/
type (
	AddRequest          = protocol.AddRequest
	DelRequest          = protocol.DelRequest
	ModifyRequest       = protocol.ModifyRequest
	ModifyRequestChange = protocol.ModifyRequestChange
	ModifyDNRequest     = protocol.ModifyDNRequest
	GenericEntry        = protocol.Entry
	Control             = protocol.Control
	Controls            = protocol.Controls
)

/*
[go-directory/syntax] type alias.

[go-directory/syntax]: https://github.com/go-directory/syntax
*/
type (
	LDAPDN     = syntax.LDAPDN
	boolean    = syntax.Boolean
	enumerated = syntax.Enumerated
)

/*
Entry implements an abstract directory entry construct, and is implemented
through an instance of any of the following types:

  - [GenericEntry] ([protocol.Entry])
  - [AddRequest] ([protocol.AddRequest])
  - [DelRequest] ([protocol.DelRequest])
  - [ModifyRequest] ([protocol.ModifyRequest])
  - [ModifyDNRequest] ([protocol.ModifyDNRequest])
*/
type Entry interface {
	DN() LDAPDN
	Choice() string // "entry" || "addRequest" || "delRequest" || "modifyRequest" || "modifyDNRequest"
}

// The LDIF struct is used for parsing an LDIF. The Controls
// is used to tell the parser to ignore any controls found
// when parsing (default: false to ignore the controls).
// FoldWidth is used for the line length when marshalling.
type LDIF struct {
	Entries    []Entry
	Version    int
	FoldWidth  int
	Controls   bool
	firstEntry bool
}

// The parseError holds the error message and the line in the ldif
// where the error occurred.
type parseError struct {
	Line    int
	Message string
}

// Error implements the error interface
func (e *parseError) Error() string {
	return "Error in line " + itoa(e.Line) + ": " + e.Message
}

var (
	cr      byte = '\x0D'
	lf      byte = '\x0A'
	sep          = string([]byte{cr, lf})
	comment byte = '#'
	space   byte = ' '
	spaces       = string(space)
)

// Parse wraps Unmarshal to parse an LDIF from a string
func Parse(str string) (l *LDIF, err error) {
	buf := bytes.NewBuffer([]byte(str))
	l = &LDIF{}
	err = Unmarshal(buf, l)
	return
}

// ParseWithControls wraps Unmarshal to parse an LDIF from
// a string, controls are added to change records
func ParseWithControls(str string) (l *LDIF, err error) {
	buf := bytes.NewBuffer([]byte(str))
	l = &LDIF{Controls: true}
	err = Unmarshal(buf, l)
	return
}

// Unmarshal parses the LDIF from the given io.Reader into the LDIF struct.
// The caller is responsible for closing the io.Reader if that is
// needed.
func Unmarshal(r io.Reader, l *LDIF) (err error) {
	for entry, err := range UnmarshalEntries(r, l) {
		if err != nil {
			return err
		}
		l.Entries = append(l.Entries, entry)
	}
	return nil
}

// UnmarshalEntries parses the LDIF from the given io.Reader and yield the individual entries during an iteration.
// The caller is responsible for closing the io.Reader if that is needed.
func UnmarshalEntries(r io.Reader, l *LDIF) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		for e, err := range unmarshalEntries(r, l) {
			if err == nil && e == nil {
				// I couldn't find use-case where the entry and the error is both nil,
				// but I saw helper functions to help avoid them,
				// so I added this logic here, to skip nil entries
				// while preserving Unmarshal's original behaviour.
				continue
			}
			if !yield(e, err) {
				return
			}
		}
	}
}

func unmarshalEntries(r io.Reader, l *LDIF) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		if r == nil {
			yield(nil, &parseError{Line: 0, Message: "No reader present"})
			return
		}

		curLine := 0
		l.Version = 0
		isComment := false

		reader := bufio.NewReader(r)

		var lines []string
		var line, nextLine string
		l.firstEntry = true

		for {
			curLine++
			var err error
			nextLine, err = reader.ReadString(lf)
			nextLine = strings.TrimRight(nextLine, sep)

			switch err {
			case nil, io.EOF:
				switch len(nextLine) {
				case 0:
					if len(line) == 0 {
						if err == io.EOF {
							return
						}
						if len(lines) == 0 {
							continue
						}
					}
					lines = append(lines, line)
					entry, perr := l.parseEntry(lines)
					if perr != nil {
						yield(nil, &parseError{Line: curLine, Message: perr.Error()})
						return
					}
					if !yield(entry, nil) {
						return
					}
					line = ""
					lines = []string{}
					if err == io.EOF {
						return
					}
				default:
					switch nextLine[0] {
					case comment:
						isComment = true
						continue

					case space:
						if isComment {
							continue
						}
						line += nextLine[1:]
						continue

					default:
						isComment = false
						if len(line) != 0 {
							lines = append(lines, line)
						}
						line = nextLine
						continue
					}
				}
			default:
				yield(nil, &parseError{Line: curLine, Message: err.Error()})
				return
			}
		}
	}
}

func (l *LDIF) parseEntry(lines []string) (entry Entry, err error) {
	if len(lines) == 0 {
		err = parserError("empty entry?")
		return
	}

	if l.firstEntry && strings.HasPrefix(lines[0], "version:") {
		l.firstEntry = false
		line := strings.TrimLeft(lines[0][8:], spaces)
		if l.Version, err = strconv.Atoi(line); err != nil {
			return
		}

		if l.Version != 1 {
			err = parserError("Invalid version spec ", string(line))
			return
		}

		l.Version = 1
		if len(lines) == 1 {
			return
		}
		lines = lines[1:]
	}
	l.firstEntry = false

	if len(lines) == 0 {
		return
	}

	if !strings.HasPrefix(lines[0], "dn:") {
		err = parserError("missing 'dn:'")
		return
	}

	var val string
	_, val, err = l.parseLine(lines[0])
	if err != nil {
		return nil, err
	}
	dn := LDAPDN(val)

	if len(lines) == 1 {
		return nil, parserError("only a dn: line")
	}
	lines = lines[1:]

	var controls []Control
	if controls, lines, err = l.parseControls(lines); err == nil {
		entry, err = l.parseEntryByChangeType(dn, lines, controls)
	}

	return
}

func (l *LDIF) parseEntryByChangeType(
	dn LDAPDN,
	lines []string,
	controls []Control,
) (entry Entry, err error) {
	var val, changeType string
	if strings.HasPrefix(lines[0], "changetype:") {
		if _, val, err = l.parseLine(lines[0]); err == nil {
			changeType = val
			if len(lines) > 1 {
				lines = lines[1:]
			}
		}
	}

	switch changeType {
	case "":
		if len(controls) != 0 {
			err = parserError("controls found without changetype")
			break
		}

		var attrs map[string][]string
		if attrs, err = l.parseAttrs(lines); err == nil {
			entry = protocol.NewEntry(dn, attrs)
		}

	case "add":
		var attrs map[string][]string
		if attrs, err = l.parseAttrs(lines); err == nil {
			// FIXME: controls for add - see https://github.com/go-ldap/ldap/issues/81
			add := AddRequest{Entry: dn}
			for attr, vals := range attrs {
				add.Attribute(attributeDesc(attr), str2AV(vals)...)
			}
			entry = add
		}

	case "delete":
		if len(lines) > 1 {
			err = parserError("no attributes allowed for changetype delete")
			break
		}
		entry = DelRequest(dn)

	case "modify":
		entry, err = l.parseEntryModCase(dn, lines)

	case "moddn", "modrdn":
		// TODO: modifydn
		err = errMDNNotImpl

	default:
		err = parserError("invalid changetype '", changeType, "'")
	}

	return
}

func (l *LDIF) parseEntryModCase(dn LDAPDN, lines []string) (entry Entry, err error) {
	// FIXME: controls for modify - see https://github.com/go-ldap/ldap/issues/81
	mod := &ModifyRequest{Object: dn}
	var op, attribute string
	var values []attributeValue
	if lines[len(lines)-1] != "-" {
		err = parserError("modify request does not close with a single dash")
		return
	}

	for i := 0; i < len(lines) && err == nil; i++ {
		if lines[i] == "-" {
			switch op {
			case "":
				err = parserError("empty operation")
			case "add":
				mod.Add(attributeDesc(attribute), values...)
				op = ""
				attribute = ""
				values = nil
			case "replace":
				mod.Replace(attributeDesc(attribute), values...)
				op = ""
				attribute = ""
				values = nil
			case "delete":
				mod.Delete(attributeDesc(attribute), values...)
				op = ""
				attribute = ""
				values = nil
			default:
				err = parserError("invalid operation '", op, "' in modify request")
			}
			continue
		}

		var attr, val string
		if attr, val, err = l.parseLine(lines[i]); err == nil {
			if op == "" {
				op = attr
				attribute = val
			} else {
				if attr != attribute {
					err = parserError("invalid attribute '", attr,
						"' in '", op, "' request for ", attribute)
				}
				values = append(values, attributeValue(val))
			}
		}
	}
	entry = mod
	return
}

func (l *LDIF) parseAttrs(lines []string) (map[string][]string, error) {
	attrs := make(map[string][]string)
	for i := 0; i < len(lines); i++ {
		attr, val, err := l.parseLine(lines[i])
		if err != nil {
			return nil, err
		}
		attrs[attr] = append(attrs[attr], val)
	}
	return attrs, nil
}

func str2AV(str []string) (av []attributeValue) {
	for i := 0; i < len(str); i++ {
		av = append(av, attributeValue(str[i]))
	}

	return
}

func (l *LDIF) parseLine(line string) (attr, val string, err error) {
	off := 0
	for len(line) > off && line[off] != ':' {
		off++
		if off >= len(line) {
			err = parserError("missing : in line '", line, "'")
			return
		}
	}
	if off == len(line) {
		err = parserError("missing : in line '", line, "'")
		return
	}

	attr = line[0:off]
	if err = validAttr(attr); err != nil {
		attr = ""
		val = ""
		return
	}

	// A line of the form "attr:" with nothing after the colon is a
	// zero-length value, which RFC 2849 (note 5) requires to be supported
	// (e.g. "seeAlso:").
	if off == len(line)-1 {
		return attr, "", nil
	}

	switch line[off+1] {
	case ':':
		val, err = decodeBase64(strings.TrimLeft(line[off+2:], spaces))
		if err != nil {
			return
		}

	case '<':
		val, err = readURLValue(strings.TrimLeft(line[off+2:], spaces))
		if err != nil {
			return
		}

	default:
		val = strings.TrimLeft(line[off+1:], spaces)
	}

	return
}

func (l *LDIF) parseControls(lines []string) ([]Control, []string, error) {
	var controls Controls
	var err error
	for err == nil {
		if !strings.HasPrefix(lines[0], "control:") {
			break
		}
		if !l.Controls {
			if len(lines) == 1 {
				err = parserError("only controls found")
				break
			}
			lines = lines[1:]
			continue
		}

		var val string
		_, val, err = l.parseLine(lines[0])
		if err != nil {
			break
		}

		var oid, ctrlValue string
		criticality := boolean(false)

		parts := strings.SplitN(val, " ", 3)
		if err = validOID(parts[0]); err != nil {
			err = parserError(oid, " is not a valid object identifier: ", err.Error())
			break
		}

		oid = parts[0]

		if len(parts) > 1 {
			switch parts[1] {
			case "true", "false":
				criticality = parts[1] == "true"
				if len(parts) > 2 {
					// a controlValue follows the criticality token
					parts = []string{parts[0], parts[2]}
				} else {
					// criticality only, no controlValue
					parts = parts[:1]
				}
			}
		}

		if len(parts) == 2 {
			ctrlValue = parts[1]
		}

		if ctrlValue == "" {
			switch oid {
			case string(protocol.OIDControlTypeManageDsaIT):
				controls = append(controls, &protocol.ControlManageDsaIT{Criticality: criticality})
			default:
				err = parserError("unsupported control found: ", oid)
			}
		} else {
			_, err = l.parseControlsValue(oid, ctrlValue) // this makes no sense to me :/ - JC
			// TODO:
			// convert ctrlValue to *ber.Packet and decode with something like
			//   ctrl := dua.DecodeControl()
			// ... FIXME: the controls need a Decode() interface
			// so we can just do a
			//   ctrl := dua.ControlByOID(oid) // returns an empty &ControlSomething{}
			//   ctrl.Decode((*ber.Packet)(ctrlValue))
			//   ctrl.Criticality = criticality
			// that should be usable in github.com/go-ldap/ldap/control.go also
			// to decode the incoming control
			// controls = append(controls, ctrl)
		}

		if len(lines) == 1 {
			err = parserError("only controls found")
			break
		}
		lines = lines[1:]
	}

	return controls, lines, err
}

func (l *LDIF) parseControlsValue(oid, ctrlValue string) (val string, err error) {
	switch ctrlValue[0] { // where is this documented? No idea, dude.
	case ':':
		if len(ctrlValue) == 1 {
			err = parserError("missing value for base64 encoded control value")
			return
		}

		ctrlValue, err = decodeBase64(strings.TrimLeft(ctrlValue[1:], spaces))
		if err == nil {
			if ctrlValue == "" {
				err = parserError("base64 decoded to empty value")
			}
		}

	case '<':
		if len(ctrlValue) == 1 {
			err = parserError("missing value for url control value")
			break
		}

		ctrlValue, err = readURLValue(strings.TrimLeft(ctrlValue[1:], spaces))
		if err == nil {
			if ctrlValue == "" {
				err = parserError("url resolved to an empty value")
			}
		}
	}

	if err == nil {
		err = parserError("controls with values are not supported, oid: ", oid)
	}
	val = ctrlValue

	return
}

func readURLValue(val string) (string, error) {
	u, err := url.Parse(val)
	if err != nil {
		return "", parserError("failed to parse URL: ", err.Error())
	}
	if u.Scheme != "file" {
		return "", parserError("unsupported URL scheme ", u.Scheme)
	}
	data, err := os.ReadFile(toPath(u))
	if err != nil {
		return "", parserError("failed to read ", u.Path, ": ", err.Error())
	}
	val = string(data) // FIXME: safe?
	return val, nil
}

func decodeBase64(enc string) (d string, err error) {
	dec := make([]byte, base64.StdEncoding.DecodedLen(len([]byte(enc))))
	var n int
	if n, err = base64.StdEncoding.Decode(dec, []byte(enc)); err == nil {
		d = string(dec[:n])
	}
	return
}

// TODO: swap out for quick LDAPOID syntax check
func validOID(oid string) error {
	lastDot := true
	for _, c := range oid {
		switch {
		case c == '.' && lastDot:
			return parserError("OID with at least 2 consecutive dots")
		case c == '.':
			lastDot = true
		case c >= '0' && c <= '9':
			lastDot = false
		default:
			return parserError("invalid character in OID")
		}
	}
	return nil
}

func validAttr(attr string) error {
	if len(attr) == 0 {
		return parserError("empty attribute name")
	}
	switch {
	case attr[0] >= 'A' && attr[0] <= 'Z':
		// A-Z
	case attr[0] >= 'a' && attr[0] <= 'z':
		// a-z
	default:
		if attr[0] >= '0' && attr[0] <= '9' {
			return validOID(attr)
		}
		return parserError("invalid first character in attribute")
	}
	for i := 1; i < len(attr); i++ {
		c := attr[i]
		switch {
		case isDigit(c), isLower(c), isUpper(c):
		case c == '-', c == ';':
		default:
			return parserError("invalid character in attribute name")
		}
	}
	return nil
}

func isDigit(r byte) bool { return '0' <= r && r <= '9' }
func isLower(r byte) bool { return 'a' <= r && r <= 'z' }
func isUpper(r byte) bool { return 'A' <= r && r <= 'Z' }

/*
AllEntries returns slices of *[GenericEntry].
*/
func (l *LDIF) AllEntries() (entries []Entry) {
	for _, entry := range l.Entries {
		entries = append(entries, entry)
	}
	return entries
}

func toPath(u *url.URL) string {
	return u.Path
}
