# -*- coding: utf-8 -*-
"""QNXProbe Autopsy data-source ingest adapter (Jython 2.7)."""
import os
import subprocess
from java.util.logging import Level
from org.sleuthkit.autopsy.ingest import (IngestModuleFactoryAdapter, DataSourceIngestModule, IngestModule)
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger

class QNXProbeFactory(IngestModuleFactoryAdapter):
    moduleName = "QNXProbe"
    def getModuleDisplayName(self): return self.moduleName
    def getModuleDescription(self): return "Read-only QNXProbe filesystem scan and extraction report"
    def getModuleVersionNumber(self): return "0.1.0"
    def isDataSourceIngestModuleFactory(self): return True
    def createDataSourceIngestModule(self, settings): return QNXProbeModule()

class QNXProbeModule(DataSourceIngestModule):
    def __init__(self):
        self.context = None
        self.log = Logger.getLogger("QNXProbe")
    def startUp(self, context):
        self.context = context
        self.python = os.environ.get("QNXPROBE_PYTHON", "python")
        self.script = os.environ.get("QNXPROBE_SCRIPT", "")
        self.exporter = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "export_free_extents.py")
        self.extract = os.environ.get("QNXPROBE_EXTRACT", "0") == "1"
        if not self.script or not os.path.isfile(self.script):
            raise IngestModuleException("Set QNXPROBE_SCRIPT to the absolute path of qnxprobe.py")
    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()
        try:
            # Image.getPaths() returns original paths. Do not silently scan a
            # split acquisition as independent segments.
            paths = list(dataSource.getPaths())
            if not paths:
                raise ValueError("No image path: only image data sources supported")
            image = str(paths[0])
            if not os.path.isfile(image):
                raise ValueError("Image path not accessible: " + image)
            case = Case.getCurrentCase()
            output = os.path.join(case.getModuleDirectory(), "QNXProbe")
            if not os.path.isdir(output): os.makedirs(output)
            stem = "datasource_%s" % str(dataSource.getId())
            report = os.path.join(output, stem + "_report.txt")
            commands = [[self.python, self.script, image]]
            if os.path.isfile(self.exporter):
                commands.append([self.python, self.exporter, image,
                                 "--output", os.path.join(output, stem + "_free_extents.json")])
            if self.extract:
                commands.append([self.python, self.script, "--extract",
                                 os.path.join(output, stem + "_recovered.zip"), image])
            with open(report, "wb") as fp:
                for cmd in commands:
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK
                    proc = subprocess.Popen(cmd, stdout=fp, stderr=subprocess.STDOUT)
                    while proc.poll() is None:
                        if self.context.isJobCancelled():
                            proc.terminate()
                            proc.wait()
                            self.log.log(Level.WARNING, "QNXProbe cancelled")
                            return IngestModule.ProcessResult.OK
                        import time
                        time.sleep(0.25)
                    if proc.returncode:
                        raise RuntimeError("QNXProbe exit code %d; see %s" % (proc.returncode, report))
            self.log.log(Level.INFO, "QNXProbe report: " + report)
        except Exception as exc:
            self.log.log(Level.SEVERE, "QNXProbe failed: " + str(exc))
            return IngestModule.ProcessResult.ERROR
        return IngestModule.ProcessResult.OK
    def shutDown(self): pass
