# Node.js / Microsoft Authentication Library / TypeScript / Docker

This is a base package of a Microsoft Authentication Web Application that was based on the starter from MS for a Node.js web Application.

I've converted the JavaScript, `js`, source files converted to TypeScript, `ts`, and moved the files into a sub-directory named `/src`. I adjusted the paths in `app.ts` file to go up a level when setting where the `views` and `public` folder are after the move. I went through the source files and adjustmented each to resolve Typescript errors and warnings. I also updated the dotenv to the more recent version and took the contents of the `msalConfig` file into each code file that required the contents. Other than these changes this should be identical to what was provided with the started source code.

To make this project create a portable image I added the Docker service with 2 image layers. First is to Build the project that uses TypeScript to produce a build and place the output into the `dist` folder. Second layer the copies the required folders from the build layer into a final layer that produces teh resulting image that can be run. I've also created a `dockerrun.cmd` file with a command line statement that would run the image locally based on environmental variables that are the be contained within a `.env` file that is in the root of the project.

There would be a requirement to create a `.env` file in the root of the project. This should look something like the following:

<blockquote><small><i>Replace any of the yellow highlighted fields with your own Azure App Registration values.</i></small></blockquote>
<pre><code><i style="color: lightgrey">#.env</i>

CLOUD_INSTANCE=https://login.microsoftonline.com/ <i># Keep trailing forward slash</i>

PORT=3080 <i># This is the Port number on your local environment</i>
REDIRECT_URI=http://localhost:3080/auth/redirect <i># Adjust the Port number if different than above</i>
POST_LOGOUT_REDIRECT_URI=http://localhost:3080 <i># Adjust the Port number if different than above</i>

GRAPH_API_ENDPOINT=https://graph.microsoft.com/ <i># Keep trailing forward slash</i>

EXPRESS_SESSION_SECRET=Express_Session_Secret <i># This is adjustable to whatever name you wish to give the Session</i>

TENANT_ID=<mark><i>Azure Subscription Tenant ID</i></mark>
CLIENT_ID=<mark><i>Azure Application Registration Client ID</i></mark>
CLIENT_SECRET=<mark><i>The Client Secret <b>Value</b> within the App Registration</i></mark>
</code></pre>

If you use the above contents by copying the code and with to use it while testing the produced Docker image you should remove any comments before running the Docker Run command that uses the `.env` file or you will recieve and error during the run.
