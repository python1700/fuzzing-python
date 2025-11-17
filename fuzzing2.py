"""
Web App Fuzzer - PyQt5 GUI (with results table + colored highlights)
Usage:
pip install PyQt5 requests
python web_app_fuzzer_pyqt5.py

Warning: Only test systems you are authorized to test.
"""

import sys
import threading
import time
import json
import csv
import urllib.parse
import re
from collections import defaultdict

import requests
from PyQt5 import QtWidgets, QtCore, QtGui

# ---------- Minimal payloads and utilities (same heuristics as CLI fuzzer) ----------
PAYLOADS = {
    'xss': [
        "<script>alert(1)</script>",
        '"><svg/onload=alert(1)>',
        "'\"><img src=x onerror=alert(1)>",
    ],
    'sqli': [
        "' OR '1'='1",
        '" OR ""="',
        "' UNION SELECT NULL--",
    ],
    'cmd': [
        ';id',
        '||uname -a',
    ],
    'path': [
        '../../etc/passwd',
        '..\\..\\windows\\win.ini',
    ],
}

ERROR_SIGNATURES = [
    r"SQL syntax", r"mysql_fetch", r"ORA-", r"UNION SELECT", r"Warning: ", r"Fatal error", r"Traceback (most recent call last)",
]

REFLECTION_THRESHOLD = 0.6


def find_error_signatures(text):
    found = []
    for sig in ERROR_SIGNATURES:
        if re.search(sig, text, re.IGNORECASE):
            found.append(sig)
    return found


# ---------- Fuzzer class (lightweight) ----------
class Fuzzer(QtCore.QObject):
    update_signal = QtCore.pyqtSignal(dict)  # send analysis dict
    finished_signal = QtCore.pyqtSignal()

    def __init__(self, base_url, method='GET', param=None, extra_data=None, headers=None,
                 concurrency=5, timeout=10, delay=0.0, payload_types=None, payload_file=None):
        super().__init__()
        self.base_url = base_url.rstrip()
        self.method = method.upper()
        self.param = param
        self.extra_data = extra_data or ''
        self.session = requests.Session()
        self.headers = headers or {'User-Agent': 'WebFuzzer-GUI/1.0'}
        self.concurrency = concurrency
        self.timeout = timeout
        self.delay = delay
        self.results = []
        self.payload_types = payload_types or ['xss', 'sqli', 'path', 'cmd']
        self._stop = False
        # load payload file if provided
        if payload_file:
            try:
                with open(payload_file, 'r', encoding='utf-8') as f:
                    extra = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                PAYLOADS.setdefault('xss', []).extend(extra)
            except Exception:
                pass

    def stop(self):
        self._stop = True

    def _generate_tasks(self):
        tasks = []
        for ptype in self.payload_types:
            lst = PAYLOADS.get(ptype, [])
            for pl in lst:
                tasks.append((ptype, pl))
        return tasks

    def _send(self, payload):
        try:
            if self.method == 'GET':
                if self.param:
                    parsed = urllib.parse.urlparse(self.base_url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[self.param] = [payload]
                    new_qs = urllib.parse.urlencode(qs, doseq=True)
                    url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                else:
                    url = self.base_url + urllib.parse.quote(payload)
                resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            else:
                data = {}
                if self.param:
                    data[self.param] = payload
                if self.extra_data:
                    kvs = urllib.parse.parse_qs(self.extra_data)
                    for k, v in kvs.items():
                        data[k] = v[0]
                resp = self.session.post(self.base_url, data=data, headers=self.headers, timeout=self.timeout)
            return resp
        except requests.RequestException as e:
            return e

    def _analyze(self, ptype, payload, resp):
        entry = {
            'type': ptype,
            'payload': payload,
            'status': None,
            'reflected': False,
            'errors': [],
            'length': None,
            'notes': []
        }
        if isinstance(resp, Exception):
            entry.update({'status': 'error', 'notes': [str(resp)]})
            return entry

        body = resp.text or ''
        entry['status'] = resp.status_code
        entry['length'] = len(body)

        simple = payload
        if len(simple) > 0:
            parts = [simple[i:i+4] for i in range(0, min(len(simple), 40), 4) if len(simple[i:i+4]) >= 3]
            if parts:
                found = sum(1 for part in parts if part in body)
                ratio = found / len(parts)
                if ratio >= REFLECTION_THRESHOLD:
                    entry['reflected'] = True
                    entry['notes'].append('Payload reflected in response (possible XSS).')

        errs = find_error_signatures(body)
        if errs:
            entry['errors'] = errs
            entry['notes'].append('Error signature matched: ' + ','.join(errs))

        if resp.status_code >= 500:
            entry['notes'].append('Server error (5xx) — possible crash or injection impact')

        if ptype == 'path' and ('root:' in body or 'nologin' in body or 'Windows' in body or '/etc/passwd' in body):
            entry['notes'].append('Path traversal likely — sensitive file content detected')

        if ptype == 'sqli' and re.search(r"select .*from|union select|mysql|syntax|query", body, re.IGNORECASE):
            entry['notes'].append('SQL-like output detected')

        return entry

    def run(self):
        tasks = self._generate_tasks()
        baseline_len = None
        try:
            r = self.session.get(self.base_url, headers=self.headers, timeout=self.timeout)
            baseline_len = len(r.text or '')
        except Exception:
            baseline_len = None

        total = len(tasks)
        for idx, (ptype, pl) in enumerate(tasks, 1):
            if self._stop:
                break
            resp = self._send(pl)
            analysis = self._analyze(ptype, pl, resp)
            if baseline_len and isinstance(analysis['length'], int):
                delta = abs(analysis['length'] - baseline_len)
                if delta > max(200, baseline_len * 0.2):
                    analysis['notes'].append(f'Response size delta suspicious: baseline={baseline_len} current={analysis["length"]}')
            self.results.append(analysis)
            # emit signal with progress
            report = {
                'index': idx,
                'total': total,
                'analysis': analysis
            }
            self.update_signal.emit(report)
            time.sleep(self.delay)

        self.finished_signal.emit()

    def save(self, out_prefix='fuzz_report'):
        json_path = f"{out_prefix}.json"
        csv_path = f"{out_prefix}.csv"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['type', 'payload', 'status', 'length', 'reflected', 'errors', 'notes'])
            writer.writeheader()
            for r in self.results:
                writer.writerow({
                    'type': r.get('type'),
                    'payload': r.get('payload'),
                    'status': r.get('status'),
                    'length': r.get('length'),
                    'reflected': r.get('reflected'),
                    'errors': '|'.join(r.get('errors') or []),
                    'notes': '|'.join(r.get('notes') or [])
                })
        return json_path, csv_path


# ---------- PyQt5 GUI ----------
class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Web App Fuzzer - PyQt5 GUI (educational)')
        self.resize(1000, 700)
        self._build_ui()
        self.worker = None
        self.thread = None

        # color & emoji maps
        self.emoji_map = {
            'xss': '🟡',
            'sqli': '🔴',
            'path': '🟣',
            'cmd': '🟠'
        }
        self.color_map = {
            'xss': QtGui.QColor(255, 255, 170),     # soft yellow
            'sqli': QtGui.QColor(255, 170, 170),    # soft red
            'path': QtGui.QColor(210, 170, 255),    # soft purple
            'cmd': QtGui.QColor(255, 205, 150),     # soft orange
        }

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        form = QtWidgets.QFormLayout()
        self.url_edit = QtWidgets.QLineEdit('https://example.com/login')
        self.method_combo = QtWidgets.QComboBox(); self.method_combo.addItems(['GET', 'POST'])
        self.param_edit = QtWidgets.QLineEdit('username')
        self.data_edit = QtWidgets.QLineEdit('password=pass')
        self.concurrency_spin = QtWidgets.QSpinBox(); self.concurrency_spin.setRange(1, 50); self.concurrency_spin.setValue(5)
        self.timeout_spin = QtWidgets.QSpinBox(); self.timeout_spin.setRange(1, 60); self.timeout_spin.setValue(10)
        self.delay_spin = QtWidgets.QDoubleSpinBox(); self.delay_spin.setRange(0, 5); self.delay_spin.setSingleStep(0.1)
        self.payload_types_edit = QtWidgets.QLineEdit('xss,sqli,path,cmd')
        self.payload_file_btn = QtWidgets.QPushButton('Load payload file')
        self.payload_file_label = QtWidgets.QLabel('')

        form.addRow('Target URL', self.url_edit)
        form.addRow('Method', self.method_combo)
        form.addRow('Param name', self.param_edit)
        form.addRow('Extra form data', self.data_edit)
        form.addRow('Concurrency', self.concurrency_spin)
        form.addRow('Timeout (s)', self.timeout_spin)
        form.addRow('Delay (s)', self.delay_spin)
        form.addRow('Payload types', self.payload_types_edit)
        h = QtWidgets.QHBoxLayout(); h.addWidget(self.payload_file_btn); h.addWidget(self.payload_file_label)
        form.addRow('Payload file', h)

        layout.addLayout(form)

        btn_h = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton('Start Scan')
        self.stop_btn = QtWidgets.QPushButton('Stop')
        self.save_btn = QtWidgets.QPushButton('Save Results')
        self.stop_btn.setEnabled(False)
        self.save_btn.setEnabled(False)
        btn_h.addWidget(self.start_btn); btn_h.addWidget(self.stop_btn); btn_h.addWidget(self.save_btn)
        layout.addLayout(btn_h)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # Log
        self.log = QtWidgets.QPlainTextEdit(); self.log.setReadOnly(True)
        log_widget = QtWidgets.QWidget()
        log_layout = QtWidgets.QVBoxLayout(log_widget)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.addWidget(QtWidgets.QLabel('Live Log:'))
        log_layout.addWidget(self.log)

        # Results table
        table_widget = QtWidgets.QWidget()
        table_layout = QtWidgets.QVBoxLayout(table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.addWidget(QtWidgets.QLabel('Results:'))
        self.table = QtWidgets.QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(['#', 'Type', 'Payload', 'Status', 'Length', 'Reflected', 'Errors', 'Notes'])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        table_layout.addWidget(self.table)

        splitter.addWidget(log_widget)
        splitter.addWidget(table_widget)
        splitter.setSizes([300, 400])

        layout.addWidget(splitter)

        self.progress = QtWidgets.QLabel('Idle')
        layout.addWidget(self.progress)

        # signals
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.save_btn.clicked.connect(self.save_results)
        self.payload_file_btn.clicked.connect(self.load_payload_file)

        self.payload_file_path = None

    def append_log(self, text):
        ts = QtCore.QDateTime.currentDateTime().toString('yyyy-MM-dd HH:mm:ss')
        self.log.appendPlainText(f'[{ts}] {text}')

    def load_payload_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open payload file', '', 'Text files (*.txt);;All files (*)')
        if path:
            self.payload_file_path = path
            self.payload_file_label.setText(path)
            self.append_log(f'Loaded payload file: {path}')

    def start_scan(self):
        url = self.url_edit.text().strip()
        if not url:
            QtWidgets.QMessageBox.warning(self, 'Error', 'Please provide a target URL')
            return
        method = self.method_combo.currentText()
        param = self.param_edit.text().strip() or None
        data = self.data_edit.text().strip() or None
        concurrency = self.concurrency_spin.value()
        timeout = self.timeout_spin.value()
        delay = self.delay_spin.value()
        payload_types = [t.strip() for t in self.payload_types_edit.text().split(',') if t.strip()]

        # clear table and log for a fresh run
        self.table.setRowCount(0)
        self.log.clear()

        self.worker = Fuzzer(url, method=method, param=param, extra_data=data,
                             concurrency=concurrency, timeout=timeout, delay=delay,
                             payload_types=payload_types, payload_file=self.payload_file_path)
        self.worker.update_signal.connect(self.on_update)
        self.worker.finished_signal.connect(self.on_finished)

        # run in background thread
        self.thread = threading.Thread(target=self.worker.run, daemon=True)
        self.thread.start()

        self.append_log('Scan started')
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.save_btn.setEnabled(False)
        self.progress.setText('Running...')

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.append_log('Stop requested')
            self.stop_btn.setEnabled(False)

    @QtCore.pyqtSlot(dict)
    def on_update(self, report):
        idx = report['index']; total = report['total']
        analysis = report['analysis']
        ptype = (analysis.get('type') or '').lower()

        # append to log
        self.append_log(f"[{idx}/{total}] {analysis['type']} -> status={analysis['status']} notes={'|'.join(analysis.get('notes') or [])}")
        self.progress.setText(f'{idx}/{total}')

        # add to table
        row = self.table.rowCount()
        self.table.insertRow(row)

        # # column
        item_idx = QtWidgets.QTableWidgetItem(str(idx))
        item_idx.setFlags(item_idx.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 0, item_idx)

        # Type column with emoji
        emoji = self.emoji_map.get(ptype, '')
        item_type = QtWidgets.QTableWidgetItem(f"{emoji} {ptype}")
        item_type.setFlags(item_type.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 1, item_type)

        # Payload
        item_payload = QtWidgets.QTableWidgetItem(analysis.get('payload') or '')
        item_payload.setFlags(item_payload.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 2, item_payload)

        # Status
        item_status = QtWidgets.QTableWidgetItem(str(analysis.get('status')))
        item_status.setFlags(item_status.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 3, item_status)

        # Length
        item_len = QtWidgets.QTableWidgetItem(str(analysis.get('length')))
        item_len.setFlags(item_len.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 4, item_len)

        # Reflected
        item_ref = QtWidgets.QTableWidgetItem(str(bool(analysis.get('reflected'))))
        item_ref.setFlags(item_ref.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 5, item_ref)

        # Errors
        item_err = QtWidgets.QTableWidgetItem('|'.join(analysis.get('errors') or []))
        item_err.setFlags(item_err.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 6, item_err)

        # Notes
        item_notes = QtWidgets.QTableWidgetItem('|'.join(analysis.get('notes') or []))
        item_notes.setFlags(item_notes.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 7, item_notes)

        # Coloring: color row by type if known
        color = self.color_map.get(ptype)
        if color:
            for col in range(self.table.columnCount()):
                cell = self.table.item(row, col)
                if cell is None:
                    cell = QtWidgets.QTableWidgetItem('')
                    cell.setFlags(cell.flags() ^ QtCore.Qt.ItemIsEditable)
                    self.table.setItem(row, col, cell)
                cell.setBackground(QtGui.QBrush(color))

        # If there are explicit error signatures or reflection, add a stronger highlight (bold the notes)
        if analysis.get('errors') or analysis.get('reflected'):
            font = item_notes.font()
            font.setBold(True)
            item_notes.setFont(font)

        # auto-scroll to bottom
        self.table.scrollToBottom()

    @QtCore.pyqtSlot()
    def on_finished(self):
        self.append_log('Scan finished')
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.save_btn.setEnabled(True)
        self.progress.setText('Finished')

    def save_results(self):
        if not self.worker:
            return
        prefix, _ = QtWidgets.QFileDialog.getSaveFileName(self, 'Save report prefix (no extension)', '', 'JSON prefix (*)')
        if not prefix:
            return
        # sanitize prefix (remove extension if provided)
        prefix = prefix.rsplit('.', 1)[0]
        jpath, cpath = self.worker.save(prefix)
        self.append_log(f'Results saved: {jpath}, {cpath}')

def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
