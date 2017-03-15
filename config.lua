local config = require("lapis.config")

config("development", {
  port = 8080
})

config("production", {
  port = 80,
  num_workers = 2,
  code_cache = "on"
})
