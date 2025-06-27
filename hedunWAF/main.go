package main

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/corazawaf/coraza/v3"
)

func main() {
	// 初始化 Coraza WAF，加载规则
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(os.DirFS(".")).
		WithDirectives(`
Include rules/crs-setup.conf
Include rules/rules/*.conf
`))
	if err != nil {
		log.Fatal("初始化 Coraza 失败:", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction()
		defer tx.Close()

		// 拆分客户端 IP 和端口
		clientIP, clientPortStr, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			clientIP = r.RemoteAddr
			clientPortStr = "0"
		}
		clientPort, err := strconv.Atoi(clientPortStr)
		if err != nil {
			clientPort = 0
		}

		// 服务器端 IP 和端口，可按需修改
		serverIP := "127.0.0.1"
		serverPort := 8080

		// 处理连接
		tx.ProcessConnection(clientIP, clientPort, serverIP, serverPort)
		// 处理 URI
		tx.ProcessURI(r.RequestURI, r.Method, r.Proto)

		// 添加请求头
		for name, values := range r.Header {
			for _, v := range values {
				tx.AddRequestHeader(name, v)
			}
		}

		if interruption := tx.ProcessRequestHeaders(); interruption != nil {
			w.WriteHeader(interruption.Status)
			w.Write([]byte("请求被拦截！"))
			return
		}

		// 读取请求体
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				log.Println("读取请求体失败:", err)
			}
			// 关闭并重置 Body，方便后续处理或转发
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		// 写入请求体
		if len(bodyBytes) > 0 {
			interruption, _, err := tx.WriteRequestBody(bodyBytes)
			if err != nil {
				log.Println("写请求体失败:", err)
			}
			if interruption != nil {
				log.Printf("请求被拦截: 状态=%d, 规则ID=%s, 原因=%s", interruption.Status, interruption.RuleID, interruption.Data)
				w.WriteHeader(interruption.Status)
				w.Write([]byte("请求被拦截！"))
				return
			}
		}

		// 处理请求体
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			log.Println("处理请求体失败:", err)
		}
		if interruption != nil {
			log.Printf("请求被拦截: 状态=%d, 规则ID=%s, 原因=%s", interruption.Status, interruption.RuleID, interruption.Data)
			w.WriteHeader(interruption.Status)
			w.Write([]byte("请求被拦截！"))
			return
		}

		// 请求正常通过
		w.Write([]byte("请求通过 Coraza WAF"))
	})

	log.Println("服务器启动，监听 :8083")
	log.Fatal(http.ListenAndServe(":8083", nil))
}
