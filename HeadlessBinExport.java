import com.google.security.binexport.BinExportExporter;
import ghidra.app.util.headless.HeadlessScript;
import java.io.File;

public class HeadlessBinExport extends HeadlessScript {
  @Override
  public void run() throws Exception {
    File outFile = askFile("Select Ouput File", "Output File");
    BinExportExporter exporter = new BinExportExporter();
    exporter.export(outFile, currentProgram, currentProgram.getMemory(), monitor);
  }
}
