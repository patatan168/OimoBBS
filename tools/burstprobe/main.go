// burstprobe は隔離TLSでDATの再開・再検証・送信待ちを測る。実投稿や公開失効の証明は別に行う。
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"oimobbs/internal/compat"
	"oimobbs/internal/delivery"
	"oimobbs/internal/platform"
	"oimobbs/internal/testutil"
	"time"
)

func main() {
	listen := flag.String("listen", ":8443", "隔離サーバーの待受")
	cert := flag.String("cert", "", "隔離証明書")
	key := flag.String("key", "", "隔離鍵")
	flag.Parse()
	platform.ConfigureRuntime()
	scheduler, err := delivery.New(80000000)
	if err != nil {
		log.Fatal(err)
	}
	defer scheduler.Close()
	body := testutil.DATFixture("entropy")
	modified := time.Now().Add(-time.Hour)
	mux := http.NewServeMux()
	mux.HandleFunc("/dat", func(w http.ResponseWriter, r *http.Request) {
		compat.ServeDAT(w, r, compat.Representation{DAT: body, ETagIdentity: `"burst-identity"`, Modified: modified, Now: time.Now(), DateSafe: true, DateExact: true})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scheduler.Status())
	})
	server := &http.Server{Addr: *listen, Handler: scheduler.Wrap(mux), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384}
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}
