#!/bin/bash

# Loop through folders Day1_ to Day9_ and rename with zero-padding
for i in {1..9}
do
  for folder in Day${i}_*; do
    if [ -d "$folder" ]; then
      new_name=$(echo "$folder" | sed "s/Day${i}_/Day0${i}_/")
      mv "$folder" "$new_name"
      echo "✅ Renamed: $folder → $new_name"
    fi
  done
done

echo "🎉 Done! All folder names are now properly padded."

