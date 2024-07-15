def getarg(name): .args[] | select(.name == name) | .value;

[
  .[] | 
  select(.eventName=="file_modification") |
  getarg("file_path")
] | unique
