# 1. GitHub එකේ public/private repo එකක් හදන්න (dkx-cracker)
git init
git add dkx.py platforms.json requirements.txt lab_server.py passwords/
git commit -m "Dkx Cracker v1.0"
git remote add origin https://github.com/<YOUR_USER>/dkx-cracker.git
git push -u origin main

# 2. ඕනම terminal එකක:
git clone https://github.com/<YOUR_USER>/dkx-cracker.git
cd dkx-cracker
pip install -r requirements.txt

# 3. Run කරන්න:
python dkx.py

# Lab එකේ test කරන්න නම්:
python lab_server.py          # terminal 1
python dkx.py --fast          # terminal 2
