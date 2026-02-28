# Powder Paint Stock Monitor

Simple web app to track powder paint boxes by:

- `RAL` colour
- `Gloss`
- current weight (kg)
- checkout/check-in usage per job

## Features

- Register paint boxes with barcode/ID.
- Scan out to a job and capture weight at checkout.
- Scan back from job and capture return weight.
- Automatically calculate paint used: `out_weight - in_weight`.
- View current in-stock totals grouped by `RAL + Gloss`.
- Role-based login (`admin`, `user`).
- `user` role can only scan in/out.
- Admin job creation page (`/jobs`) to create job codes.
- Scan-out only allows existing open jobs.
- Admin can finalize jobs and view total usage per finalized job.
- Admin can delete jobs that have no stock movement history.
- Analytics page (`/analytics`) for usage by paint type, job, and month.
- Scan-out requires selecting `Line 1` or `Line 2`.
- Usage reports and analytics include line-based totals.
- Admin settings page (`/admin/database`) to change the database directory.
- Admin page can add/remove users and change access role (`admin` or `user`).
- Admin page can delete added paint boxes (only when no usage history exists).
- Database directory supports local and network locations (mounted paths and `smb://` style input).
- Box setup validation:
- `RAL` must be selected from the RAL Classic colour chart list.
- `Gloss` is restricted to `Matt`, `Semi Gloss`, or `Gloss`.
- Stock in now has its own admin page (`/stock-in`, legacy `/boxes` still works).

## Run (Production WSGI)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
waitress-serve --host=0.0.0.0 --port=2026 wsgi:app
```

Open:

`http://127.0.0.1:2026`

## Raspberry Pi Auto-Boot (Systemd)

On the Raspberry Pi:

```bash
cd /path/to/New\ project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo ./scripts/install_rpi_autostart.sh
```

This installs a `systemd` service that starts automatically on boot.

Useful commands:

```bash
systemctl status powder-paint.service
journalctl -u powder-paint.service -f
```

To access from any computer on the same network:

1. Find Pi IP:
```bash
hostname -I
```
2. Open from another computer:
`http://<raspberry-pi-ip>:2026`

If needed, allow the port:

```bash
sudo ufw allow 2026/tcp
```

## Run (Development)

```bash
python app.py
```

Open:

`http://127.0.0.1:5000`

## Login

- Admin: `admin` / `admin123`
- User: `user` / `user123`

Permissions:

- `admin`: full access
- `user`: scan out and scan in only
