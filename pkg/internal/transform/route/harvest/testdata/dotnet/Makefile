routes.dll.b64: Routes.cs routes.csproj
	dotnet build --configuration Release --output bin -p:BaseIntermediateOutputPath=bin/obj/ routes.csproj
	base64 --wrap=96 bin/routes.dll > routes.dll.b64
