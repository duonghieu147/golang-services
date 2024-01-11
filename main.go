package main

import (
  "context"
  "fmt"
  "github.com/go-redis/redis/v8"
  "github.com/gorilla/websocket"
  "hieuduong/golang-services/util"
  "log"
  "net/http"
  "sync"
)

var (
  upgrader = websocket.Upgrader{
    ReadBufferSize:  1024,
    WriteBufferSize: 1024,
    CheckOrigin: func(r *http.Request) bool {
      return true
    },
  }

  redisClient *redis.Client
  clients     = make(map[*websocket.Conn]bool)
  clientsLock sync.Mutex
  key, _      = util.GenerateRandomBytes(32)
)

type Room struct {
  clients map[*Client]bool
  mu      sync.Mutex
}

type Client struct {
  conn     *websocket.Conn
  username string
  room     *Room
}

func init() {
  redisClient = redis.NewClient(&redis.Options{
    Addr:     "localhost:6379", // Redis server address
    Password: "",               // No password
    DB:       0,                // Default DB
  })
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
  conn, err := upgrader.Upgrade(w, r, nil)
  if err != nil {
    log.Println("WebSocket upgrade error:", err)
    return
  }
  defer conn.Close()

  // Add the new connection to the list of clients
  clientsLock.Lock()
  clients[conn] = true
  clientsLock.Unlock()

  for {
    _, p, err := conn.ReadMessage()
    if err != nil {
      fmt.Println(err)

      // Remove the disconnected client from the list
      clientsLock.Lock()
      delete(clients, conn)
      clientsLock.Unlock()

      return
    }

    fmt.Println("Msg read Websocket:", p, string(p))
    encryptMgs, _ := util.Encrypt(key, string(p))
    fmt.Println("EncryptMgs : ", encryptMgs)

    // Publish the message to Redis Pub/Sub
    err = redisClient.Publish(context.Background(), "chat", encryptMgs).Err()
    if err != nil {
      fmt.Println(err)
    }
  }
}

func subscribeToRedisChannel() {
  pubsub := redisClient.Subscribe(context.Background(), "chat")
  defer pubsub.Close()

  for {
    msg, err := pubsub.ReceiveMessage(context.Background())
    if err != nil {
      fmt.Println(err)
      continue
    }
    fmt.Println("Msg receive redis:", msg.Payload)
    decryptMgs, _ := util.Decrypt(key, msg.Payload)
    fmt.Println("DecryptMgs:", decryptMgs)

    // Broadcast the message to all connected clients
    broadcastMessage([]byte(decryptMgs))
  }
}

func broadcastMessage(message []byte) {
  clientsLock.Lock()
  defer clientsLock.Unlock()

  for client := range clients {
    err := client.WriteMessage(websocket.TextMessage, message)
    if err != nil {
      fmt.Println(err)
      // Handle errors, e.g., remove the disconnected client from the list
    }
  }
}

func main() {
  fmt.Println(key)
  go subscribeToRedisChannel()

  http.HandleFunc("/ws", handleWebSocket)
  fmt.Println("WebSocket server is running on http://localhost:8080/ws")
  port := 8080
  err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
  if err != nil {
    log.Fatal("ListenAndServe: ", err)
  }
}
