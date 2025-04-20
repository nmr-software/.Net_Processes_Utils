using System.Diagnostics;
using System.Management;

namespace Tests;

[TestClass]
public class TestStarter {
    static ProcessStartInfo psi = new ProcessStartInfo() {
        FileName = "timeout.exe",
        Arguments = "/t 20",
        UseShellExecute = false,
    };

    Process p;

    [TestMethod]
    [DataRow(0, false)]
    [DataRow(Starter.CREATE_NEW_CONSOLE, true)]
    public void TestNewConsole(int flag, bool hasConhost) {
        p = Starter.StartWithFlags(psi, flag);
        Thread.Sleep(100);
        Assert.AreEqual(hasConhost, getChild() != null);
    }

    Process getChild() {
        foreach (var mo in new ManagementObjectSearcher($"Select * From Win32_Process Where Name = 'conhost.exe' and ParentProcessID={p.Id}").Get()) {
            return Process.GetProcessById(Convert.ToInt32(mo["ProcessID"]));
        }
        return null;
    }

    [TestCleanup]
    public void TestCleanup() {
        if (p != null) p.Kill();
    }

}
