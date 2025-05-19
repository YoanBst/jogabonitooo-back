# Utilise l'image officielle Deno
FROM denoland/deno:alpine

# Crée un dossier pour l'app
WORKDIR /app

# Copie tous les fichiers dans l'image Docker
COPY . .

# Expose le port sur lequel ton serveur écoute
EXPOSE 5000

# Commande de démarrage de l'application
CMD ["run", "--allow-net", "--allow-read", "--allow-env", "back_server.ts"]
