######################
### AzureBox Class ###
######################

#' @title AzureBox - A Class for Azure Authentication and User Data Retrieval
#' @description This R6 class facilitates OAuth2.0 authentication against Azure
#' AD and retrieves user data using the Microsoft Graph API.
#' @importFrom R6 R6Class
#' @import httr
#' @import shinyjs
#' @import AzureAuth
#' @import glue
#' @export
AzureBox <- R6Class(
  "AzureBox",
  public = list(
    #' @description Initialize the AzureBox class
    #' @param tenantID The Azure tenant ID.
    #' @param appID The Azure application (client) ID.
    #' @param appSecret The Azure application secret.
    #' @param redirect The redirect URI after authentication.
    initialize = function(tenantID, appID, appSecret, redirect){
      private$resource <- c("https://graph.microsoft.com/.default", "openid", "offline_access")
      private$tenant <- tenantID
      private$app <- appID
      private$password <- appSecret
      private$redirect <- redirect
      private$port <- private$ParsePort(redirect)
    },

    #' @description Retrieve an OAuth2.0 token using the authorization code from the URL.
    #' @param urlSearch The URL containing the authorization code.
    #' @return The OAuth2.0 token object.
    GetToken = function(urlSearch)
    {
      if(!is.null(private$token)) return(private$token)

      query <- parseQueryString(urlSearch)
      if(is.null(query$code))
      {
        private$RedirectToAzure()
        return(NULL)
      }

      private$CleanURL()
      query <- parseQueryString(urlSearch)
      private$token <- private$RetrieveToken(query$code)
      return(private$token)
    },

    #' @description Retrieve user data from Microsoft Graph API.
    #' @return A list containing the user data.
    GetUserData = function()
    {
      token <- private$token
      if(is.null(token)) stop("Unable to retrieve a username due there not being an Azure token found!")

      response <- GET("https://graph.microsoft.com/v1.0/me",
                      httr::add_headers(
                        Authorization = paste("Bearer", token$credentials$access_token)
                      )
      )
      if(response$status_code != 200)
      {
        private$LogDebug("Could not retrieve user data! Status code:", response$status_code)
        private$LogDebug("Error details: ", content(response, "text", encoding = "UTF-8"))
        return()
      }

      userData <- content(response, "parsed")
      return(userData)
    },

    #' @description Get the port from the redirect URI.
    #' @return The port number.
    GetPort = function()
    {
      return(private$port)
    }
  ),
  private = list(
    resource = NULL,
    tenant = NULL,
    app = NULL,
    password = NULL,
    redirect = NULL,
    port = NULL,
    token = NULL,

    ParsePort = function(redirect)
    {
      port <- httr::parse_url(redirect)$port
      if(is.null(port)) return(80)
      return(as.numeric(port))
    },

    RedirectToAzure = function()
    {
      authenticationURI <- build_authorization_uri(resource = private$resource,
                                                   tenant = private$tenant,
                                                   app = private$app,
                                                   redirect_uri = private$redirect,
                                                   version = 2)
      redirectJS <- sprintf("console.log('redirected'); location.replace(\"%s\");", authenticationURI)
      shinyjs::runjs(redirectJS)
      return()
    },

    RetrieveToken = function(code)
    {
      token <- get_azure_token(resource = private$resource,
                               tenant = private$tenant,
                               app = private$app,
                               password = private$password,
                               auth_type = "authorization_code",
                               authorize_args = list(redirect_uri = private$redirect,
                                                     response_type = "id_token"),
                               version = 2,
                               use_cache = FALSE,
                               auth_code = code)
      return(token)
    },

    CleanURL = function()
    {
      jsFunction <- sprintf("$(document).ready(function(event) {
        const nextURL = '%s';
        const nextTitle = 'My new page title';
        const nextState = { additionalInformation: 'Updated the URL with JS' };
        window.history.pushState(nextState, nextTitle, nextURL);
        console.log('cleaned url');
        });", private$redirect
      )
      shinyjs::runjs(jsFunction)
      return()
    },

    LogDebug = function(text, value = "")
    {
      shinyjs::runjs(sprintf(glue("console.log('{text} {value}')")))
    }
  )
)
