"# mock-ransomware"
1. Release\ransomware.exe
2. Go to test folder, notice the permission changes, change them back to see the encrypted text
3. Delete copied malware inside of `\\Users\\<name>\\ransomware` directory
4. open up `regedit` to also delete persistent keys
  - `reg DELETE HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ransomware_pwn /f`
  The operation completed successfully.
  - `reg QUERY HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
    - to verify
5. To view the driver installed
```
C:\> sc query MyCustomBeep

SERVICE_NAME: MyCustomBeep
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

[Disclaimer]
THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. DO NOT USE FOR MALICIOUS PURPOSES, ONLY FOR EDUCATIONAL.
