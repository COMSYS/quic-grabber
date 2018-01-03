package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"runtime"

	"os"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/qtrace"
)
import _ "net/http/pprof"
import "net/http"

type myTrace struct {
	sni      string
	addr     string
	original map[string]interface{}
	rejTags  map[string]string
	shloTags map[string]string
	error    string
}

func tagToString(tag uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(tag))
	tag_string := ""
	for i := range b {
		if b[i] == 0 {
			b[i] = ' '
		}
		tag_string += string(b[i])
	}

	return tag_string
}
func (t *myTrace) ClientGotHandshakeMsg(message qtrace.TracerHandshakeMessage) {

	var TagREJ uint32 = 'R' + 'E'<<8 + 'J'<<16
	var TagSHLO uint32 = 'S' + 'H'<<8 + 'L'<<16 + 'O'<<24
	if message.Tag == uint32(TagREJ) {
		t.rejTags = make(map[string]string)
		for tag, val := range message.Data {
			string_tag := tagToString(tag)
			t.rejTags[string_tag] = base64.StdEncoding.EncodeToString(val)
		}
	}
	if message.Tag == uint32(TagSHLO) {
		t.shloTags = make(map[string]string)
		for tag, val := range message.Data {
			string_tag := tagToString(tag)
			t.shloTags[string_tag] = base64.StdEncoding.EncodeToString(val)
		}
	}
	//fmt.Printf("Message: ", t.RejTags)
}

func DialAddrFromAddr(addr string, saddr string, tlsConf *tls.Config, config *quic.Config) (quic.Session, error, *net.UDPConn) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err, nil
	}
	ip := net.IPv4zero
	if saddr != "" {
		ip = net.ParseIP(saddr)
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		return nil, err, nil
	}
	res := make(chan struct {
		quic.Session
		error
	}, 1)
	go func() {
		sess, sesserror := quic.Dial(udpConn, udpAddr, addr, tlsConf, config)
		res <- struct {
			quic.Session
			error
		}{sess, sesserror}
		return
	}()
	select {
	case result := <-res:
		return result.Session, result.error, udpConn
	case <-time.After(12 * time.Second):
		// close the conn, then quic must fail
		udpConn.Close()
	}
	// we get here after timeout, above MUST fail eventually, channel will not block
	return nil, fmt.Errorf("General Timeout"), udpConn
}

func scan_quic(addr string, sni string, original map[string]interface{}, result_chan chan<- *myTrace) {
	t := &myTrace{sni: sni, addr: addr, original: original}
	comm := make(chan struct {
		quic.Session
		error
		*net.UDPConn
	}, 1)

	go func(t *myTrace) {
		session, err, sock := DialAddrFromAddr(t.addr, *src_ip, &tls.Config{InsecureSkipVerify: true, ServerName: t.sni}, &quic.Config{QuicTracer: qtrace.Tracer{ClientGotHandshakeMsg: t.ClientGotHandshakeMsg}})

		comm <- struct {
			quic.Session
			error
			*net.UDPConn
		}{session, err, sock}

	}(t)
	select {
	case result := <-comm:
		if result.error != nil {
			t.error = result.error.Error()
			if result.Session != nil {
				result.Session.Close(nil)
			}
			if result.UDPConn != nil {
				result.UDPConn.Close()
			}
		} else {
			result.Session.Close(nil)
			result.UDPConn.Close()
		}
		result_chan <- t
		close(comm)
	}
}

func line_from_stdin(stdin_chan chan<- string, running_chan chan<- bool) {
	fscanner := bufio.NewScanner(os.Stdin)
	maxsize := 64 * 1024 * 1024
	inbuff := make([]byte, maxsize, maxsize)
	fscanner.Buffer(inbuff, maxsize)
	for fscanner.Scan() {
		running_chan <- true
		stdin_chan <- fscanner.Text()
	}
	close(stdin_chan)
}

var src_ip = flag.String("source-ip", "", "Set the source IP")
var num_concurrent = flag.Int("parallel", 10, "Number of parallel pacing estimations")
var profile = flag.String("profile", "", "Opens pprof on port 6060 on this ip")

func main() {

	log.Println("Startup")
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()
	enc := json.NewEncoder(os.Stdout)
	os.Stdout.Sync()
	enc.SetEscapeHTML(false)

	if *profile != "" {
		log.Println("Starting profiler")
		go func() {
			log.Println(http.ListenAndServe(*profile+":6060", nil))
		}()
	}

	result_chan := make(chan *myTrace)

	stdin_chan := make(chan string, 1)
	running_chan := make(chan bool, *num_concurrent)
	running := true

	go line_from_stdin(stdin_chan, running_chan)
	for len(running_chan) > 0 || running {

		select {
		case line, ok := <-stdin_chan:
			if ok {

				var inline map[string]interface{}
				if err := json.Unmarshal([]byte(line), &inline); err != nil {
					log.Printf("Error parsing json: %s (%s)\n", err.Error(), line)
					break
				}

				go scan_quic(inline["addr"].(string), inline["sni"].(string), inline, result_chan)

			} else {

				running = false

			}

		case result := <-result_chan:
			if result.rejTags != nil {
				result.original["rejTags"] = result.rejTags
			}
			if result.shloTags != nil {
				result.original["shloTags"] = result.shloTags
			}
			if result.error != "" {
				result.original["error"] = result.error
			}
			enc.Encode(result.original)

			<-running_chan

		}

	}
	log.Println("Shutdown")
}
