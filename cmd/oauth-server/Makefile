
run:
	@go run main.go \
	-listen=":8080" \
	-oauth-client-id="$(shell teamvault-username --teamvault-config=~/.teamvault.json --teamvault-key=aqMAJq)" \
	-oauth-secret="$(shell teamvault-password --teamvault-config=~/.teamvault.json --teamvault-key=aqMAJq)" \
	-redirect-uri http://localhost:8080/callback \
	-v=2
