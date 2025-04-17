using System.Diagnostics;

[TestClass]
public class TestThreadInjector {

    Process p;
    String last;

    [TestInitialize]
    public void Start() {
        p = Process.Start(new ProcessStartInfo() {
            FileName = "timeout.exe",
            Arguments = "/t 2",
            UseShellExecute = false,
            RedirectStandardError = true,
        });
        p.ErrorDataReceived += (_, s) => last = s.Data;
    }


    [TestMethod]
    public void ProcessExitsWithoutInjection() {
        Assert.IsFalse(p.WaitForExit(500), "Process should not have exited yet");
        Assert.IsTrue(p.WaitForExit(3000), "Process should have exited");
    }

    [TestMethod]
    public void TestInjectCausingSuspension() {
        var i = new ThreadInjector(p);
        i.Inject();
        Assert.IsFalse(p.WaitForExit(3000), "Process should not have exited");
        Assert.AreEqual(1, p.Threads.Count, "Process should have 1 thread left");
        Assert.AreEqual(ThreadWaitReason.Suspended, p.Threads[0].WaitReason, "Thread should be suspended");
    }

    [TestMethod]
    public void TestWritesOutput() {
        p.BeginErrorReadLine();
        var i = new ThreadInjector(p);
        i.Inject();
        Thread.Sleep(3000);
        Assert.IsTrue(last.Contains("Zombie suspend on DLL_PROCESS_DETACH"));
    }

    [TestMethod]
    [DataRow(true, DisplayName = "Threads called")]
    [DataRow(false, DisplayName = "Threads not called")]
    public void TestResume(bool callThreadsBefore) {
        if (callThreadsBefore) {
            var _ = p.Threads;
        }
        var i = new ThreadInjector(p);
        i.Inject();
        Assert.IsFalse(p.WaitForExit(3000));

        i.Continue();
        Assert.IsTrue(p.WaitForExit(1000));
    }

    [TestCleanup]
    public void TestCleanup() {
        p.Kill();
    }
}
