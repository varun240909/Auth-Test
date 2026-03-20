import "dotenv/config";
import app from "./src/app.js";
import ConnectMongoose from "./src/config/mongoose.js";

await ConnectMongoose();
const PORT = process.env.PORT || 3009;

const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

process.on("SIGINT", () => {
  console.log("Shutting down server...");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});
