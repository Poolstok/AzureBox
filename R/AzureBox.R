######################
### AzureBox Class ###
######################

#' @title AzureBox - A Class for Azure Authentication and User Data Retrieval
#' @description This R6 class facilitates OAuth2.0 authentication against Azure
#' AD and retrieves user data using the Microsoft Graph API. The class should be
#' instantiated in a module that runs at app startup. After object initialization (AzureBox$new()),
#' run AzureBox$GetToken() with as argument the value of session$clientData$url_search.
#' This can be done by using shiny's isolate() function.
#' @examples
#' /dontrun{
#'   azureBox <- AzureBox$new(tenantID = "your-tenant-id",# The tenant id of your organization, can be found after registering a new application in Microsoft Azure/Entra
#'                appID = "your-app-id",                  # Can be found in Azure/Entra aftering registering a new application
#'                appSecret = "your-app-secret",          # Create one for your app using Microsoft Azure/Entra
#'                redirect = "redirect-link-to-your-url") # Must match with the app redirect set in Microsoft Azure/Entra
#'
#'  token <- azureBox$GetToken(isolate(session$clientData$url_search)) # Token is also stored internally within the AzureBox class
#'
#'  # Internal storage of token within AzureBox makes it possible to retrieve userData after authentication
#'  userData <- azureBox$GetUserData()
#' }
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
      private$defaultFieldsToGet <- c("id", "displayName", "mail", "userPrincipalName", "jobTitle", "employeeId", "employeeType", "jobTitle", "photo")
    },

    #' @description Retrieve an OAuth2.0 token using the authorization code from the URL.
    #' @param urlSearch The URL containing the authorization code. Can be retrieved using
    #' `isolate(session$clientData$url_search)`
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
    #'   Should only be run after getting a token using AzureBox$GetToken().
    #' @param select_fields A character vector of fields to retrieve (e.g., c("employeeID", "employeeType")). Defaults to NULL, which retrieves all fields.
    #' @return A list containing the user data or NULL if the request fails.
    GetUserData = function(select_fields = private$defaultFieldsToGet) {
      # Retrieve the token from the private environment
      token <- private$token

      # Check if the token is available
      if (is.null(token)) {
        stop("Unable to retrieve a username due to the absence of an Azure token!")
      }

      # Base URL for the Microsoft Graph API endpoint
      base_url <- "https://graph.microsoft.com/v1.0/me"

      # Initialize query parameters list
      query_params <- list()

      # If select_fields is provided, add it to the query parameters
      if (!is.null(select_fields)) {
        if (is.character(select_fields)) {
          # Join the fields with commas as required by the $select parameter
          query_params <- list(`$select` = paste(select_fields, collapse = ","))
        } else {
          stop("select_fields must be a character vector of field names.")
        }
      }

      # Make the GET request with appropriate headers and query parameters
      response <- GET(
        url = base_url,
        httr::add_headers(
          Authorization = paste("Bearer", token$credentials$access_token)
        ),
        query = query_params
      )

      # Check if the request was successful
      if (response$status_code != 200) {
        private$LogDebug("Could not retrieve user data! Status code:", response$status_code)
        private$LogDebug("Error details: ", content(response, "text", encoding = "UTF-8"))
        return(NULL)
      }

      # Parse and return the user data
      userData <- content(response, "parsed")
      return(userData)
    },
    #' @description Get the port from the redirect URI. This can be useful when redirecting
    #' to a localhost uri (e.g. http//localhost:8000) to set the app to run on the
    #' same port using options=list(shiny.port = azureBox$GetPort())
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
    defaultFieldsToGet = NULL,

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

      debug_message <- paste(text, value, sep = " ")
      # Output the message to the console
      message("[DEBUG] ", debug_message)
    }
  )
)
