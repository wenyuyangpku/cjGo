package main

import (
	"context"
	"github.com/appleboy/gin-jwt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net/http"
	// "reflect"
	"time"
)

var identityKey = "id"

// Message is the message sended by user
type Message struct {
	Message string `json:"message"`
}

// ObjectID is the BSON ObjectID type.
// type ObjectID [12]byte

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func wshandler(w http.ResponseWriter, r *http.Request) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))

	if err != nil {
		log.Fatal(err)
	}

	collection := client.Database("testing").Collection("messages")

	upgrader.CheckOrigin = func(r *http.Request) bool { return true }

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Println(err)
			return
		}

		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var result bson.M

		options := options.FindOne().SetSort(bson.D{primitive.E{Key: "_id", Value: -1}})

		err = collection.FindOne(ctx, bson.D{}, options).Decode(&result)
		if err != nil {
			log.Fatal(err)
		}

		if err != nil {
			log.Fatal(err)
		}

		if err := conn.WriteJSON(result); err != nil {
			log.Println(err)
			return
		}

	}
}

type login struct {
	Tel      string `form:"tel" json:"tel" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
	Username string `form:"username" json:"username"`
}

type guild struct {
	Name  string             `form:"name" json:"name" binding:"required"`
	Owner primitive.ObjectID `form:"owner" json:"owner" `
}

// User demo
type User struct {
	Tel      string
	UserName string
}

func connectDB(collectionName string) *mongo.Collection {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))

	if err != nil {
		log.Fatal(err)
	}

	collection := client.Database("testing").Collection(collectionName)

	return collection
}

func authCallback(c *gin.Context) (interface{}, error) {
	userCollection := connectDB("user")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var loginVals login
	if err := c.ShouldBind(&loginVals); err != nil {
		return "", jwt.ErrMissingLoginValues
	}
	tel := loginVals.Tel
	password := loginVals.Password
	username := loginVals.Username

	if username != "" {
		var result bson.M

		err := userCollection.FindOne(ctx, bson.M{"tel": tel}).Decode(&result)

		if err != nil {

			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := userCollection.InsertOne(ctx, loginVals)

			if err != nil {
				log.Fatal(err)
			}

			return &User{
				Tel:      tel,
				UserName: username,
			}, nil

		}
		return nil, jwt.ErrForbidden

	}
	var result bson.M

	err := userCollection.FindOne(ctx, bson.M{"tel": tel, "password": password}).Decode(&result)

	if err != nil {
		return nil, jwt.ErrFailedAuthentication
	}

	return &User{
		Tel:      tel,
		UserName: username,
	}, nil
}

func userInfo(c *gin.Context) {
	claims := jwt.ExtractClaims(c)

	userCollection := connectDB("user")

	guildsCollection := connectDB("guilds")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result bson.M
	err := userCollection.FindOne(ctx, bson.M{"tel": claims[identityKey]}).Decode(&result)
	if err != nil {
		log.Fatal(err)
	}

	var guilds primitive.A

	if guildsID, ok := (result["guilds"]).(primitive.A); ok {
		for _, guildID := range guildsID {

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var guild bson.M
			err = guildsCollection.FindOne(ctx, bson.M{"_id": guildID}).Decode(&guild)
			if err != nil {
				log.Fatal(err)
			}

			guilds = append(guilds, guild)

		}
	}

	c.JSON(200, bson.M{"username": result["username"], "guilds": guilds})

}

func guilds(c *gin.Context) {
	claims := jwt.ExtractClaims(c)

	var guildVals guild

	if err := c.ShouldBind(&guildVals); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "wrong format"})
		return
	}

	guildsCollection := connectDB("guilds")

	userCollection := connectDB("user")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result bson.M
	err := userCollection.FindOne(ctx, bson.M{"tel": claims[identityKey]}).Decode(&result)
	if err != nil {
		log.Fatal(err)
	}

	if owner, ok := (result["_id"]).(primitive.ObjectID); ok {
		guildVals.Owner = owner
	}

	// log.Println(guildVals.Owner)
	// log.Println(reflect.TypeOf(result["_id"]))

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := guildsCollection.InsertOne(ctx, guildVals)
	if err != nil {
		log.Fatal(err)
	}
	guildID := res.InsertedID

	filter := bson.D{primitive.E{Key: "_id", Value: guildVals.Owner}}
	update := bson.D{primitive.E{Key: "$push", Value: bson.D{primitive.E{Key: "guilds", Value: guildID}}}}

	_, err = userCollection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		log.Fatal(err)
	}

	c.JSON(200, gin.H{"guildID": guildID})
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowMethods:     []string{"GET", "POST", "OPTIONS", "PUT"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "User-Agent", "Referrer", "Host", "Token", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowAllOrigins:  true,
		// AllowOrigins: []string{"https://cijian.net", "http://localhost:3000/"},
		MaxAge: 86400,
	}))

	//http://www.atomicgain.com/go-gin-jwt/
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Key:         []byte("FE880BE1D7558D62B1DFDAE3E7D4F82ED9E987FA12D9195A18312741A1F87858"),
		IdentityKey: identityKey,
		Timeout:     time.Hour * 10,
		MaxRefresh:  time.Hour * 1000,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					identityKey: v.Tel,
				}
			}
			return jwt.MapClaims{}
		},
		Authenticator: authCallback,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	r.POST("/auth/login", authMiddleware.LoginHandler)

	r.POST("/auth/register", authMiddleware.LoginHandler)

	r.GET("/auth/refresh_token", authMiddleware.RefreshHandler)

	api := r.Group("/api")

	api.Use(authMiddleware.MiddlewareFunc())
	{
		api.GET("/info", userInfo)

		api.POST("/guilds", guilds)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))

	if err != nil {
		log.Fatal(err)
	}

	collection := client.Database("testing").Collection("messages")

	r.GET("/ws", func(c *gin.Context) {
		wshandler(c.Writer, c.Request)
	})

	r.POST("/message", func(c *gin.Context) {

		var message struct {
			Message string `json:"message" binding:"required"`
		}

		if c.Bind(&message) == nil {

			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			res, err := collection.InsertOne(ctx, bson.M{"message": message.Message, "time": time.Now()})
			id := res.InsertedID

			if err != nil {
				log.Fatal(err)
			}

			c.JSON(http.StatusOK, gin.H{"status": "ok", "id": id})
		}

	})

	r.GET("/messages", func(c *gin.Context) {

		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cur, err := collection.Find(ctx, bson.D{})
		if err != nil {
			log.Fatal(err)
		}
		defer cur.Close(ctx)

		var results []bson.M
		for cur.Next(ctx) {
			var result bson.M
			err := cur.Decode(&result)
			if err != nil {
				log.Fatal(err)
			}

			results = append(results, result)
		}
		if err := cur.Err(); err != nil {
			log.Fatal(err)
		}

		c.JSON(http.StatusOK, gin.H{"status": "ok", "result": results})
	})

	return r
}

func main() {

	r := setupRouter()

	r.Run()

}
