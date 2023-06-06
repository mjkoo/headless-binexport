/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// An example of building a single minimal Ghidra jar file.
//@category Examples

import generic.jar.ApplicationModule;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.util.GhidraJarBuilder;
import java.io.File;
import java.util.List;

// This script creates a minimal jar file with most gui modules and help files
// removed. To create a complete Ghidra jar file, add all modules and remove the
// excluded file extensions.

public class BuildGhidraJarScript extends GhidraScript {

  @Override
  public void run() throws Exception {
    GhidraJarBuilder builder =
        new GhidraJarBuilder(Application.getApplicationLayout());

    builder.setMainClass("ghidra.JarRun");

    builder.removeAllProcessorModules();

    builder.addModule("AARCH64");
    builder.addModule("ARM");
    builder.addModule("MIPS");
    builder.addModule("PowerPC");
    builder.addModule("x86");

    builder.addModule("BinExport");

    builder.removeModule("ByteViewer");
    builder.removeModule("DMG");
    builder.removeModule("Debugger");
    builder.removeModule("Debugger-agent-dbgeng");
    builder.removeModule("Debugger-agent-dbgmodel");
    builder.removeModule("Debugger-agent-dbgmodel-traceloader");
    builder.removeModule("Debugger-agent-frida");
    builder.removeModule("Debugger-agent-gadp");
    builder.removeModule("Debugger-agent-gdb");
    builder.removeModule("Debugger-agent-isf");
    builder.removeModule("Debugger-agent-jdpa");
    builder.removeModule("Debugger-agent-lldb");
    builder.removeModule("Debugger-agent-swig-lldb");
    builder.removeModule("Debugger-gadp");
    builder.removeModule("Debugger-isf");
    builder.removeModule("Debugger-jdpa");
    builder.removeModule("Debugger-swig-lldb");
    builder.removeModule("SystemEmulation");
    builder.removeModule("TaintAnalysis");

    List<ApplicationModule> moduleList = builder.getIncludedModules();
    for (ApplicationModule module : moduleList) {
      println("Include " + module.getName());
    }
    moduleList = builder.getExcludedModules();
    for (ApplicationModule module : moduleList) {
      println("Exclude " + module.getName());
    }

    // don't include help or processor manuals
    builder.addExcludedFileExtension(".htm");
    builder.addExcludedFileExtension(".html");
    builder.addExcludedFileExtension(".pdf");

    File installDir = Application.getInstallationDirectory().getFile(true);
    builder.buildJar(new File(installDir, "ghidra.jar"), null, monitor);

    // uncomment the following line to create a src zip for debugging.
    // builder.buildSrcZip(new File(installDir, "GhidraSrc.zip"), monitor);
  }
}
