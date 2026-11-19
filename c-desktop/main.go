package main

import (
	"log"
	"net/http"

	"fleetops/c-desktop/internal/nativehttp"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/fetch"
)

func main() {
	connections := nativehttp.New()
	mygo.Bind(connections)
	mygo.Use(fetch.New(fetch.Options{
		Client: nativehttp.Client(connections),
		Allow:  func(r *http.Request) bool { return nativehttp.Allow(connections, r) },
	}))
	mygo.App.WhenReady(func() {
		win := mygo.NewWindow(mygo.WindowOptions{
			Title: "FleetOps", Width: 1280, Height: 860,
			MinWidth: 760, MinHeight: 560,
			BackgroundColor: "#f4f6fa", StateKey: "main", URL: "/",
		})
		win.Page().OnWillNavigate(func(event *mygo.NavigateEvent) { event.PreventDefault() })
		win.Page().SetWindowOpenHandler(func(mygo.WindowOpenRequest) *mygo.WindowOptions { return nil })
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
