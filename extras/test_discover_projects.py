import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import automation
from discover_projects import discover

class DiscoveryTests(unittest.TestCase):
    def test_multilanguage_nested_and_excluded(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            markers=['java/pom.xml','gradle/build.gradle.kts','js/package.json','js/package-lock.json','py/pyproject.toml','php/composer.lock','go/go.mod','rust/Cargo.toml','ruby/Gemfile','net/app.csproj','node_modules/ignore/package.json','vendor/ignore/pom.xml','java/module/pom.xml']
            for name in markers:
                p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_text('not executed')
            result=discover([raw,raw])
            self.assertEqual(result['status'],'complete')
            self.assertEqual(len(result['projects']),10)
            self.assertEqual({x['kind'] for x in result['projects']},{'java','javascript','python','php','go','rust','ruby','dotnet'})
            self.assertEqual(len(result['scan_inputs']),2)
            self.assertTrue(all(x['dependency_analysis']=='unsupported' for x in result['projects'] if x['kind']=='java'))

    def test_symlinks_and_limits(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); (root/'pom.xml').write_text('')
            (root/'loop').symlink_to(root,target_is_directory=True)
            (root/'linked.json').symlink_to(root/'pom.xml')
            self.assertEqual(discover([raw])['coverage']['symlinks_skipped'],2)
            self.assertEqual(discover([str(root/'loop')])['status'],'degraded')
            self.assertEqual(discover([raw],max_entries=1)['status'],'degraded')
            (root/'sub').mkdir()
            self.assertEqual(discover([raw],max_depth=0)['status'],'degraded')

    def test_permission_and_missing_root_are_not_clean(self):
        with tempfile.TemporaryDirectory() as raw:
            with patch('discover_projects.os.scandir',side_effect=PermissionError('denied')):
                self.assertEqual(discover([raw])['status'],'degraded')
            self.assertEqual(discover([str(Path(raw)/'absent')])['status'],'degraded')

    def test_cycle_discovers_and_parses_without_network_or_build(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); project=root/'projects/app'; project.mkdir(parents=True)
            (project/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'node_modules/example':{'version':'1.2.3'}}}))
            (project/'pom.xml').write_text('<project/>')
            config={'schema':'secbrief-automation/config-v1','runner':str(Path(__file__).with_name('secbrief_extra.py').resolve()),'output':str(root/'out'),'state_dir':str(root/'state'),'online':False,'discovery':{'roots':['projects']}}
            path=root/'config.json'; path.write_text(json.dumps(config))
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(automation.cycle(path),0)
            report=json.loads((root/'out/report.json').read_text())
            self.assertEqual(len(report['project_discovery']['projects']),2)
            self.assertEqual(report['assets'][0]['version'],'1.2.3')
            with contextlib.redirect_stdout(io.StringIO()) as output: self.assertEqual(automation.cycle(path),0)
            self.assertEqual(json.loads(output.getvalue())['status'],'nochange')
            (project/'go.mod').write_text('module example')
            with contextlib.redirect_stdout(io.StringIO()) as output: self.assertEqual(automation.cycle(path),0)
            self.assertTrue(json.loads(output.getvalue())['discovery_changed'])
            (project/'child').mkdir(); config['discovery']['max_depth']=0; path.write_text(json.dumps(config))
            with contextlib.redirect_stdout(io.StringIO()) as output: self.assertEqual(automation.cycle(path),2)
            self.assertEqual(json.loads(output.getvalue())['status'],'failed')

if __name__=='__main__': unittest.main()
