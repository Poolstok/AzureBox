library(shiny)
library(httr)
library(R6)
library(AzureAuth)
source("../R/AzureBox.R")
library(shinyjs)

testUI <- function() {
    return(
        fluidPage(
            useShinyjs(),
            uiOutput("data")
        )
    )
}

ConvertListToUI <- function(listData)
{
    ui <- tagList()
    for(name in names(listData))
    {
        itemUI <- tagList(
            strong(paste0(name, ": ")),
            listData[[name]],
            br()
        )
        ui <- tagList(ui, itemUI)
    }
    return(ui)
}

testServer <- function(input, output, session)
{
    azureTestBox <- AzureBox$new(Sys.getenv("AZURE_TENANT_ID"),
                                 Sys.getenv("AZURE_CLIENT_ID"),
                                 Sys.getenv("AZURE_CLIENT_SECRET"),
                                 Sys.getenv("REDIRECT"))
    azureTestBox$CaptureToken(isolate(session$clientData$url_search))
    token <- reactiveVal(azureTestBox$GetToken(isolate(session$clientData$url_search)))

    output$data <- renderUI({
        req(token())

        userData <- azureTestBox$GetUserData(select_fields = NULL)
        userUI <- ConvertListToUI(userData)
        return(
            userUI
        )
    })
}

shinyApp(ui = testUI, server = testServer, options = list(port = 8000))
