import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import subprocess
import threading
import time
from pathlib import Path
import psutil

class USBRecoveryTool:
    def __init__(self, root):
        self.root = root
        self.root.title("USB 바이러스 복구 툴 v2.0")
        self.root.geometry("700x600")
        self.root.resizable(True, True)
        
        # 선택된 경로
        self.selected_path = tk.StringVar()
        
        # 진행 상태
        self.is_running = False
        
        self.setup_ui()
        self.refresh_usb_drives()
        
    def setup_ui(self):
        """UI 구성"""
        # 메인 프레임
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 제목
        title_label = ttk.Label(main_frame, text="USB 바이러스 복구 툴", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # USB 드라이브 감지 섹션
        usb_frame = ttk.LabelFrame(main_frame, text="USB 드라이브 감지", padding="10")
        usb_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.usb_listbox = tk.Listbox(usb_frame, height=4)
        self.usb_listbox.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=(0, 5))
        self.usb_listbox.bind('<<ListboxSelect>>', self.on_usb_select)
        
        refresh_btn = ttk.Button(usb_frame, text="새로고침", command=self.refresh_usb_drives)
        refresh_btn.grid(row=0, column=2, sticky=tk.N)
        
        # 경로 선택 섹션
        path_frame = ttk.LabelFrame(main_frame, text="경로 선택", padding="10")
        path_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(path_frame, text="선택된 경로:").grid(row=0, column=0, sticky=tk.W)
        
        path_entry = ttk.Entry(path_frame, textvariable=self.selected_path, width=50)
        path_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        browse_btn = ttk.Button(path_frame, text="폴더 선택", command=self.browse_folder)
        browse_btn.grid(row=1, column=1)
        
        # 복구 옵션 섹션
        options_frame = ttk.LabelFrame(main_frame, text="복구 옵션", padding="10")
        options_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # 버튼들을 2x2 그리드로 배치
        btn_frame = ttk.Frame(options_frame)
        btn_frame.grid(row=0, column=0, columnspan=2, pady=5)
        
        self.hidden_btn = ttk.Button(btn_frame, text="숨김 파일/폴더 복구", 
                                    command=self.recover_hidden_files, width=25)
        self.hidden_btn.grid(row=0, column=0, padx=(0, 5), pady=2)
        
        self.system_btn = ttk.Button(btn_frame, text="시스템 파일 속성 제거", 
                                    command=self.remove_system_attributes, width=25)
        self.system_btn.grid(row=0, column=1, padx=(5, 0), pady=2)
        
        self.readonly_btn = ttk.Button(btn_frame, text="읽기 전용 속성 제거", 
                                      command=self.remove_readonly_attributes, width=25)
        self.readonly_btn.grid(row=1, column=0, padx=(0, 5), pady=2)
        
        self.scan_btn = ttk.Button(btn_frame, text="바이러스 검사 & 정리", 
                                  command=self.scan_and_clean, width=25)
        self.scan_btn.grid(row=1, column=1, padx=(5, 0), pady=2)
        
        # 고급 복구 옵션
        advanced_frame = ttk.Frame(options_frame)
        advanced_frame.grid(row=1, column=0, columnspan=2, pady=(10, 0))
        
        self.recycle_btn = ttk.Button(advanced_frame, text="휴지통에서 복구", 
                                     command=self.recover_from_recycle, width=25)
        self.recycle_btn.grid(row=0, column=0, padx=(0, 5))
        
        self.deep_scan_btn = ttk.Button(advanced_frame, text="딥 스캔 복구", 
                                       command=self.deep_scan_recovery, width=25)
        self.deep_scan_btn.grid(row=0, column=1, padx=(5, 0))
        
        # 진행률 표시
        progress_frame = ttk.LabelFrame(main_frame, text="진행 상황", padding="10")
        progress_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.progress_var = tk.StringVar(value="대기 중...")
        ttk.Label(progress_frame, textvariable=self.progress_var).grid(row=0, column=0, sticky=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # 로그 출력 섹션
        log_frame = ttk.LabelFrame(main_frame, text="작업 로그", padding="10")
        log_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=12, width=80)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 그리드 가중치 설정
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        path_frame.columnconfigure(0, weight=1)
        progress_frame.columnconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
    def log_message(self, message):
        """로그 메시지 추가"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
    def refresh_usb_drives(self):
        """USB 드라이브 목록 새로고침"""
        self.usb_listbox.delete(0, tk.END)
        
        # 리무버블 드라이브 감지
        drives = []
        for partition in psutil.disk_partitions():
            if 'removable' in partition.opts or partition.fstype in ['FAT32', 'exFAT', 'NTFS']:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    size_gb = usage.total / (1024**3)
                    free_gb = usage.free / (1024**3)
                    drive_info = f"{partition.device} ({size_gb:.1f}GB, 여유:{free_gb:.1f}GB) - {partition.fstype}"
                    self.usb_listbox.insert(tk.END, drive_info)
                    drives.append(partition.device.rstrip('\\'))
                except:
                    continue
                    
        self.drive_paths = drives
        self.log_message(f"USB 드라이브 {len(drives)}개 감지됨")
        
    def on_usb_select(self, event):
        """USB 드라이브 선택 시"""
        selection = self.usb_listbox.curselection()
        if selection:
            index = selection[0]
            if index < len(self.drive_paths):
                self.selected_path.set(self.drive_paths[index])
                
    def browse_folder(self):
        """폴더 선택 다이얼로그"""
        folder = filedialog.askdirectory(title="복구할 폴더를 선택하세요")
        if folder:
            self.selected_path.set(folder)
            
    def validate_path(self):
        """경로 유효성 검사"""
        path = self.selected_path.get().strip()
        if not path:
            messagebox.showerror("오류", "복구할 경로를 선택해주세요.")
            return False
            
        if not os.path.exists(path):
            messagebox.showerror("오류", f"선택한 경로가 존재하지 않습니다:\n{path}")
            return False
            
        return True
        
    def run_command_thread(self, command, success_msg, error_msg):
        """명령어를 별도 스레드에서 실행"""
        def run():
            try:
                self.is_running = True
                self.progress_bar.start()
                
                if isinstance(command, list):
                    result = subprocess.run(command, capture_output=True, text=True, shell=True)
                else:
                    result = subprocess.run(command, capture_output=True, text=True, shell=True)
                
                if result.returncode == 0:
                    self.log_message(f"✓ {success_msg}")
                    if result.stdout.strip():
                        self.log_message(f"출력: {result.stdout.strip()}")
                else:
                    self.log_message(f"✗ {error_msg}")
                    if result.stderr.strip():
                        self.log_message(f"오류: {result.stderr.strip()}")
                        
            except Exception as e:
                self.log_message(f"✗ 실행 중 오류: {str(e)}")
            finally:
                self.is_running = False
                self.progress_bar.stop()
                self.progress_var.set("작업 완료")
                
        threading.Thread(target=run, daemon=True).start()
        
    def recover_hidden_files(self):
        """숨김 파일/폴더 복구"""
        if not self.validate_path() or self.is_running:
            return
            
        path = self.selected_path.get()
        self.progress_var.set("숨김 파일 복구 중...")
        self.log_message(f"숨김 파일 복구 시작: {path}")
        
        # attrib 명령어로 숨김 속성 제거
        command = f'attrib -h -s /s /d "{path}\\*.*"'
        self.run_command_thread(command, 
                               "숨김 파일/폴더 복구 완료", 
                               "숨김 파일 복구 중 오류 발생")
        
    def remove_system_attributes(self):
        """시스템 파일 속성 제거"""
        if not self.validate_path() or self.is_running:
            return
            
        path = self.selected_path.get()
        self.progress_var.set("시스템 속성 제거 중...")
        self.log_message(f"시스템 속성 제거 시작: {path}")
        
        command = f'attrib -s /s /d "{path}\\*.*"'
        self.run_command_thread(command,
                               "시스템 속성 제거 완료",
                               "시스템 속성 제거 중 오류 발생")
        
    def remove_readonly_attributes(self):
        """읽기 전용 속성 제거"""
        if not self.validate_path() or self.is_running:
            return
            
        path = self.selected_path.get()
        self.progress_var.set("읽기 전용 속성 제거 중...")
        self.log_message(f"읽기 전용 속성 제거 시작: {path}")
        
        command = f'attrib -r /s /d "{path}\\*.*"'
        self.run_command_thread(command,
                               "읽기 전용 속성 제거 완료",
                               "읽기 전용 속성 제거 중 오류 발생")
        
    def scan_and_clean(self):
        """바이러스 파일 검사 및 정리"""
        if not self.validate_path() or self.is_running:
            return
            
        path = self.selected_path.get()
        self.progress_var.set("바이러스 검사 중...")
        self.log_message(f"바이러스 검사 시작: {path}")
        
        def scan():
            try:
                self.is_running = True
                self.progress_bar.start()
                
                # 의심스러운 파일 패턴
                suspicious_patterns = [
                    '*.lnk',  # 바이러스가 만든 바로가기
                    'autorun.inf',  # 자동실행 파일
                    '*.vbs',  # VBS 스크립트
                    '*.bat',  # 배치 파일
                    '*.cmd',  # 명령 파일
                ]
                
                found_files = []
                for pattern in suspicious_patterns:
                    command = f'dir "{path}\\{pattern}" /s /b 2>nul'
                    result = subprocess.run(command, capture_output=True, text=True, shell=True)
                    if result.stdout.strip():
                        files = result.stdout.strip().split('\n')
                        found_files.extend(files)
                
                if found_files:
                    self.log_message(f"의심스러운 파일 {len(found_files)}개 발견:")
                    for file in found_files[:10]:  # 최대 10개만 표시
                        self.log_message(f"  - {file}")
                    if len(found_files) > 10:
                        self.log_message(f"  ... 및 {len(found_files)-10}개 더")
                else:
                    self.log_message("의심스러운 파일이 발견되지 않았습니다.")
                
                # 모든 속성 복구
                command = f'attrib -h -r -s /s /d "{path}\\*.*"'
                result = subprocess.run(command, capture_output=True, text=True, shell=True)
                self.log_message("파일 속성 복구 완료")
                
            except Exception as e:
                self.log_message(f"✗ 검사 중 오류: {str(e)}")
            finally:
                self.is_running = False
                self.progress_bar.stop()
                self.progress_var.set("검사 완료")
                
        threading.Thread(target=scan, daemon=True).start()
        
    def recover_from_recycle(self):
        """휴지통에서 복구 시도"""
        if not self.validate_path() or self.is_running:
            return
            
        self.progress_var.set("휴지통 검사 중...")
        self.log_message("휴지통에서 파일 복구 시도...")
        
        def recover():
            try:
                self.is_running = True
                self.progress_bar.start()
                
                # Windows 휴지통 경로들
                recycle_paths = [
                    os.path.join(os.environ.get('SystemDrive', 'C:'), '$Recycle.Bin'),
                    os.path.join(os.environ.get('SystemDrive', 'C:'), 'RECYCLER')
                ]
                
                found_files = 0
                for recycle_path in recycle_paths:
                    if os.path.exists(recycle_path):
                        for root, dirs, files in os.walk(recycle_path):
                            found_files += len(files)
                            
                self.log_message(f"휴지통에서 {found_files}개 파일 발견")
                self.log_message("수동으로 휴지통을 확인하여 복구하세요.")
                
                # 휴지통 열기
                os.system('start shell:RecycleBinFolder')
                
            except Exception as e:
                self.log_message(f"✗ 휴지통 접근 오류: {str(e)}")
            finally:
                self.is_running = False
                self.progress_bar.stop()
                self.progress_var.set("휴지통 검사 완료")
                
        threading.Thread(target=recover, daemon=True).start()
        
    def deep_scan_recovery(self):
        """딥 스캔으로 삭제된 파일 복구"""
        if not self.validate_path() or self.is_running:
            return
            
        path = self.selected_path.get()
        self.progress_var.set("딥 스캔 중...")
        self.log_message(f"딥 스캔 시작: {path}")
        
        def deep_scan():
            try:
                self.is_running = True
                self.progress_bar.start()
                
                # 파일 시스템 체크
                drive = path[:2] if ':' in path else path
                command = f'chkdsk {drive} /f /r'
                
                self.log_message("파일 시스템 무결성 검사 중...")
                self.log_message("주의: 이 작업은 관리자 권한이 필요할 수 있습니다.")
                
                result = subprocess.run(f'echo y | {command}', 
                                      capture_output=True, text=True, shell=True)
                
                if "액세스가 거부" in result.stderr:
                    self.log_message("관리자 권한으로 실행해야 합니다.")
                else:
                    self.log_message("딥 스캔 완료")
                
                # 파일 복구 시도
                command = f'attrib -h -r -s /s /d "{path}\\*.*"'
                subprocess.run(command, capture_output=True, text=True, shell=True)
                
                self.log_message("파일 속성 복구 완료")
                
            except Exception as e:
                self.log_message(f"✗ 딥 스캔 오류: {str(e)}")
            finally:
                self.is_running = False
                self.progress_bar.stop()
                self.progress_var.set("딥 스캔 완료")
                
        # 확인 다이얼로그
        if messagebox.askyesno("딥 스캔 확인", 
                              "딥 스캔은 시간이 오래 걸릴 수 있습니다.\n계속하시겠습니까?"):
            threading.Thread(target=deep_scan, daemon=True).start()

def main():
    """메인 실행 함수"""
    root = tk.Tk()
    app = USBRecoveryTool(root)
    
    # 창 종료 시 확인
    def on_closing():
        if app.is_running:
            if messagebox.askokcancel("종료 확인", "작업이 진행 중입니다. 정말 종료하시겠습니까?"):
                root.destroy()
        else:
            root.destroy()
            
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()