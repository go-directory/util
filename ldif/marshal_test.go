package ldif_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/go-directory/protocol"
	"github.com/go-directory/util/ldif"
)

var personLDIF = `dn: uid=someone,ou=people,dc=example,dc=org
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: someone
cn: Someone
mail: someone@example.org

`

var ouLDIF = `dn: ou=people,dc=example,dc=org
objectClass: top
objectClass: organizationalUnit
ou: people

`

func av(a string) protocol.AttributeValue {
	return protocol.AttributeValue(a)
}
func ad(a string) protocol.AttributeDescription {
	return protocol.AttributeDescription(a)
}

var entries = []protocol.Entry{
	{
		Name: protocol.LDAPDN("ou=people,dc=example,dc=org"),
		Attributes: []protocol.EntryAttribute{
			{
				Type: []byte("objectClass"),
				Vals: []protocol.AttributeValue{
					av("top"),
					av("organizationalUnit"),
				},
			},
			{
				Type: []byte("ou"),
				Vals: []protocol.AttributeValue{av("people")},
			},
		},
	},
	{
		Name: protocol.LDAPDN("uid=someone,ou=people,dc=example,dc=org"),
		Attributes: []protocol.EntryAttribute{
			{
				Type: []byte("objectClass"),
				Vals: []protocol.AttributeValue{
					av("top"),
					av("person"),
					av("organizationalPerson"),
					av("inetOrgPerson"),
				},
			},
			{
				Type: []byte("uid"),
				Vals: []protocol.AttributeValue{av("someone")},
			},
			{
				Type: []byte("cn"),
				Vals: []protocol.AttributeValue{av("Someone")},
			},
			{
				Type: []byte("mail"),
				Vals: []protocol.AttributeValue{av("someone@example.org")},
			},
		},
	},
}

func nPeople(n int) ([]protocol.Entry, string) {
	nEntries := make([]protocol.Entry, n+1)
	var builder strings.Builder

	nEntries[0] = entries[0]
	builder.WriteString(ouLDIF)

	for i := 1; i <= n; i++ {
		nEntries[i] = protocol.Entry{
			Name: []byte(fmt.Sprintf("uid=someone%d,ou=people,dc=example,dc=org", i)),
			Attributes: []protocol.EntryAttribute{
				{
					Type: []byte("objectClass"),
					Vals: []protocol.AttributeValue{
						av("top"),
						av("person"),
						av("organizationalPerson"),
						av("inetOrgPerson"),
					},
				},
				{
					Type: []byte("uid"),
					Vals: []protocol.AttributeValue{av(fmt.Sprintf("someone%d", i))},
				},
				{
					Type: []byte("cn"),
					Vals: []protocol.AttributeValue{av(fmt.Sprintf("Someone%d", i))},
				},
				{
					Type: []byte("mail"),
					Vals: []protocol.AttributeValue{av(fmt.Sprintf("someone%d@example.org", i))},
				},
			},
		}

		builder.WriteString(fmt.Sprintf(""+
			"dn: uid=someone%d,ou=people,dc=example,dc=org\n"+
			"objectClass: top\n"+
			"objectClass: person\n"+
			"objectClass: organizationalPerson\n"+
			"objectClass: inetOrgPerson\n"+
			"uid: someone%d\n"+
			"cn: Someone%d\n"+
			"mail: someone%d@example.org\n"+
			"\n",
			i, i, i, i))
	}

	return nEntries, builder.String()
}

func BenchmarkMarshalNEntries(b *testing.B) {
	benchmarker := func(n int, stream string, writeWith func(callback func(writer io.Writer, reader io.Reader) error) error) {
		b.Run(fmt.Sprintf("marshal %d %s", n, stream), func(b *testing.B) {
			entries, expected := nPeople(n)
			ldifEntries := make([]ldif.Entry, len(entries))
			for i, entry := range entries {
				ldifEntries[i] = entry
			}
			l := &ldif.LDIF{Entries: ldifEntries}

			err := writeWith(func(writer io.Writer, reader io.Reader) error {
				err := ldif.MarshalStreaming(l, writer)
				if err != nil {
					return err
				}

				if seeker, ok := reader.(io.Seeker); ok {
					_, err := seeker.Seek(0, io.SeekStart)
					if err != nil {
						return err
					}
				}

				all, err := io.ReadAll(reader)
				if err != nil {
					return err
				}

				actual := string(all)

				if actual != expected {
					b.Errorf("expected: >>%s<<\nactual: >>%s<<\n", expected, actual)
				}

				return nil
			})

			if err != nil {
				b.Errorf("Failed to marshal entry: %s", err)
			}
		})
	}

	writers := []struct {
		name      string
		writeWith func(callback func(writer io.Writer, reader io.Reader) error) error
	}{
		{
			name: "file",
			writeWith: func(callback func(writer io.Writer, reader io.Reader) error) error {
				file, err := os.CreateTemp(os.TempDir(), "ldif_test")

				if err != nil {
					return err
				}

				err = callback(file, file)

				if err != nil {
					return err
				}

				return file.Close()
			},
		},
		{
			name: "bytebuffer",
			writeWith: func(callback func(writer io.Writer, reader io.Reader) error) error {
				var b bytes.Buffer
				return callback(&b, &b)
			},
		},
	}

	for _, tt := range writers {
		benchmarker(100, tt.name, tt.writeWith)
		benchmarker(1000, tt.name, tt.writeWith)
		benchmarker(10000, tt.name, tt.writeWith)
		benchmarker(100000, tt.name, tt.writeWith)
	}

}

func TestMarshalSingleEntry(t *testing.T) {
	e1 := entries[1]
	l := &ldif.LDIF{
		Entries: []ldif.Entry{&e1},
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != personLDIF {
		t.Errorf("unexpected result: >>%s<<\n", res)
	}
}

func TestMarshalEntries(t *testing.T) {
	e1 := entries[0]
	e2 := entries[1]
	l := &ldif.LDIF{
		Entries: []ldif.Entry{&e1, &e2},
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != ouLDIF+personLDIF {
		t.Errorf("unexpected result: >>%s<<\n", res)
	}
}

func TestMarshalB64(t *testing.T) {
	entryLDIF := `dn: ou=people,dc=example,dc=org
objectClass: top
objectClass: organizationalUnit
ou: people
description:: VGhlIFBlw7ZwbGUgw5ZyZ2FuaXphdGlvbg==

`
	entry := &protocol.Entry{
		Name: protocol.LDAPDN("ou=people,dc=example,dc=org"),
		Attributes: []protocol.EntryAttribute{
			{
				Type: []byte("objectClass"),
				Vals: []protocol.AttributeValue{
					av("top"),
					av("organizationalUnit"),
				},
			},
			{
				Type: []byte("ou"),
				Vals: []protocol.AttributeValue{av("people")},
			},
			{
				Type: []byte("description"),
				Vals: []protocol.AttributeValue{av("The Peöple Örganization")},
			},
		},
	}
	l := &ldif.LDIF{
		Entries: []ldif.Entry{entry},
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != entryLDIF {
		t.Errorf("unexpected result: >>%s<<\n", res)
	}
}

func TestMarshalLeadingTrailingSpace(t *testing.T) {
	// Values that begin or end with a space must be base64 encoded so they
	// survive a round-trip (RFC 2849 SAFE-INIT-CHAR / note 8).
	entry := &protocol.Entry{
		Name: protocol.LDAPDN("uid=someone,dc=example,dc=org"),
		Attributes: []protocol.EntryAttribute{
			{Type: []byte("description"), Vals: []protocol.AttributeValue{av(" leading")}},
			{Type: []byte("title"), Vals: []protocol.AttributeValue{av("trailing ")}},
			{Type: []byte("colon"), Vals: []protocol.AttributeValue{av(":value")}},
			{Type: []byte("lt"), Vals: []protocol.AttributeValue{av("<value")}},
		},
	}
	l := &ldif.LDIF{Entries: []ldif.Entry{entry}}
	out, err := ldif.Marshal(l)
	if err != nil {
		t.Fatalf("Failed to marshal: %s", err)
	}
	// The leading-space value must be emitted with the base64 marker "::" and
	// the correct encoding, not verbatim.
	if strings.Contains(out, "description:  leading") {
		t.Errorf("leading-space value was emitted verbatim:\n%s", out)
	}
	for _, wantLine := range []string{
		"description:: " + base64.StdEncoding.EncodeToString([]byte(" leading")),
		"title:: " + base64.StdEncoding.EncodeToString([]byte("trailing ")),
		"colon:: " + base64.StdEncoding.EncodeToString([]byte(":value")),
		"lt:: " + base64.StdEncoding.EncodeToString([]byte("<value")),
	} {
		if !strings.Contains(out, wantLine) {
			t.Errorf("expected %q in output, got:\n%s", wantLine, out)
		}
	}

	l2, err := ldif.Parse(out)
	if err != nil {
		t.Fatalf("Failed to re-parse marshalled output: %s\n%s", err, out)
	}
	got := l2.Entries[0].(protocol.Entry)
	for attr, want := range map[string]string{
		"description": " leading",
		"title":       "trailing ",
		"colon":       ":value",
		"lt":          "<value",
	} {
		if v := got.GetAttributeValue(ad(attr)); !v.Equal(av(want)) {
			t.Errorf("%s lost in round-trip: got %q, want %q", attr, v, want)
		}
	}
}

func TestMarshalMod(t *testing.T) {
	modLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: modify
replace: sn
sn: One
-
add: givenName
givenName: Some
-
delete: mail
-
delete: telephoneNumber
telephoneNumber: 123 456 789 - 0
-

`
	mod := protocol.ModifyRequest{Object: []byte("uid=someone,ou=people,dc=example,dc=org")}
	mod.Replace(ad("sn"), av("One"))
	mod.Add(ad("givenName"), av("Some"))
	mod.Delete(ad("mail"))
	mod.Delete(ad("telephoneNumber"), av("123 456 789 - 0"))
	l := &ldif.LDIF{
		Entries: []ldif.Entry{&mod},
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != modLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

func TestMarshalAdd(t *testing.T) {
	addLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: someone
cn: Someone
mail: someone@example.org

`
	add := protocol.AddRequest{Entry: []byte("uid=someone,ou=people,dc=example,dc=org")}
	for _, a := range entries[1].Attributes {
		add.Attribute(a.Type, a.Vals...)
	}
	l := &ldif.LDIF{
		Entries: []ldif.Entry{&add},
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != addLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

func TestMarshalDel(t *testing.T) {
	delLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: delete

`
	del := protocol.DelRequest("uid=someone,ou=people,dc=example,dc=org")
	l := &ldif.LDIF{
		Entries: []ldif.Entry{&del},
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != delLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

func TestDump(t *testing.T) {
	delLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: delete

`
	del := protocol.DelRequest("uid=someone,ou=people,dc=example,dc=org")
	buf := bytes.NewBuffer(nil)
	err := ldif.Dump(buf, 0, &del)
	if err != nil {
		t.Errorf("Failed to dump entry: %s", err)
	}
	res := buf.String()
	if res != delLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}
