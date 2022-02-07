1. Log into the Microsoft Azure Management Console.
2. Select the "Search resources, services, and docs" option at the top and search for App Services. ![Step](/resources/azure/appservice/client-certificates-enabled/step2.png)
3. Select the "App Services" by clicking on the "Name" link to access the configuration changes.![Step](/resources/azure/appservice/client-certificates-enabled/step3.png)
4. Scroll down the selected "App Services" navigation panel and in "Settings" click on the "TLS/SSL settings" option.</br <img src="/resources/azure/appservice/client-certificates-enabled/step4.png"/>
5. On the "TLS/SSL settings" page check if "Incoming client certificates" is "ON/OFF". If it's turned "OFF" then it will not block all clients who do not have a valid certificate from accessing the app. ![Step](/resources/azure/appservice/client-certificates-enabled/step5.png)
6. Repeat steps number 2 - 5 to verify other "Apps" SSL settings in the account.</br>
7. Navigate to the "App Services", select the "App Service" and click on the "Name" as a link to access the configuration, select the "TLS/SSL settings" under "Settings."![Step](/resources/azure/appservice/client-certificates-enabled/step7.png)
8. On the "Protocol Settings" page click on the "ON" option next to "Incoming client certificates" which only allows clients with valid certificates to reach the app. ![Step](/resources/azure/appservice/client-certificates-enabled/step8.png)
9. Repeat above steps to ensures "Client Certificates" are enabled for "App Services", only allowing clients with valid certificates to reach the app.