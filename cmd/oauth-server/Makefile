
run:
	@OAUTH_PROVIDER=google go run main.go \
	-listen=":8080" \
	-oauth-client-id="$(shell teamvault-username --teamvault-config=~/.teamvault.json --teamvault-key=aqMAJq)" \
	-oauth-secret="$(shell teamvault-password --teamvault-config=~/.teamvault.json --teamvault-key=aqMAJq)"
