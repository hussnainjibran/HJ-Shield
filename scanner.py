import os
import hashlib
import shutil

print("================================")
print("        HJ SHIELD 🛡️")
print("================================")

THREAT_HASHES = {
    "26b527c6debff9ce8cb0fc19b8b88840bc86f7203971b02973d6d824f0c54fe3"
}

def get_sha256(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                data = file.read(65536)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except (PermissionError, OSError):
        return None


folder = input("\nFolder path: ")

if not os.path.isdir(folder):
    print("❌ Folder nahi mila.")
    raise SystemExit

quarantine_folder = os.path.join(folder, "quarantine")
os.makedirs(quarantine_folder, exist_ok=True)

print("\n🔍 HJ Shield scanning...\n")

files_checked = 0
threats = 0

for root, folders, files in os.walk(folder):

    # Quarantine folder ko dobara scan nahi karna
    if os.path.abspath(root) == os.path.abspath(quarantine_folder):
        continue

    for filename in files:

        file_path = os.path.join(root, filename)
        file_hash = get_sha256(file_path)

        if file_hash is None:
            continue

        files_checked += 1
        print("Checking:", filename)

        if file_hash in THREAT_HASHES:

            print("🚨 THREAT DETECTED:", file_path)

            try:
                destination = os.path.join(
                    quarantine_folder,
                    filename
                )

                # Same filename ho to safe unique name
                if os.path.exists(destination):
                    base, extension = os.path.splitext(filename)
                    destination = os.path.join(
                        quarantine_folder,
                        base + "_quarantined" + extension
                    )

                shutil.move(file_path, destination)

                print("🔒 Moved to quarantine:", destination)
                threats += 1

            except (PermissionError, OSError) as error:
                print("❌ Could not quarantine:", error)

print("\n================================")
print("          SCAN COMPLETE")
print("================================")
print("Files checked:", files_checked)
print("Threats detected:", threats)

if threats == 0:
    print("✅ No known threats detected.")
else:
    print("🔒 Detected files were moved to quarantine.")

print("================================")