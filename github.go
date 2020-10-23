package gosocialsessions

import (
	"fmt"
	"net/http"

	"github.com/dghubble/gologin/v2"
	"github.com/dghubble/gologin/v2/github"
	"golang.org/x/oauth2"
	githubOAuth2 "golang.org/x/oauth2/github"
)

func (self *SessionManager) GetGitHubLoginHandlers(clientID, clientSecret, callbackUrl string) (http.Handler, http.Handler) {
	// 1. Register Login and Callback handlers
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  callbackUrl,
		Endpoint:     githubOAuth2.Endpoint,
		Scopes:       []string{"email"},
	}

	// state param cookies require HTTPS by default; disable for localhost development
	stateConfig := gologin.DebugOnlyCookieConfig
	loginHandler := github.StateHandler(stateConfig, github.LoginHandler(oauth2Config, nil))
	callbackHandler := github.StateHandler(stateConfig, github.CallbackHandler(oauth2Config, self.issueGitHubSession(), nil))
	return loginHandler, callbackHandler
}

// issueSession issues a cookie session after successful Facebook login
func (self *SessionManager) issueGitHubSession() http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		githubUser, err := github.UserFromContext(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 2. Implement a success handler to issue some form of session
		session := self.issueSession()
		session.Values["userid"] = fmt.Sprintf("%v", *githubUser.ID)
		session.Values["username"] = githubUser.Login
		// session.Values["useremail"] = githubUser.Email	// <-- Not being sent...
		session.Values["useremail"] = githubUser.Login
		session.Values["usertype"] = "github"
		session.Save(w)
		http.Redirect(w, req, "/profile", http.StatusFound)
	}
	return http.HandlerFunc(fn)
}
