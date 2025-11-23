import { useState } from 'react';
import TabButton from '../components/TabButton';
import RiskBadge from '../components/RiskBadge';

const SampleAnalysisPreviewPage = () => {
  const [activeTab, setActiveTab] = useState('overview');

  // API 호출 없이 정적으로 정의된 샘플 데이터 (모든 탭용 데이터 포함)
  const sampleData = {
    title: 'Python 기반 이미지 분석 요약',
    imageTag: 'pyyaml-vuln.tar',
    tags: ['Python', '2025. 11. 17.'],
    summary: {
      riskLevel: 'CRITICAL',
      criticalCount: 1,
      highCount: 6,
      mediumCount: 5,
      lowCount: 1,
      patchSets: 5,
      patchTargets: 'PyYAML, Werkzeug, setuptools',
      callPaths: 2
    },
    highlights: [
      'Flask 2.0.2 (CVE-2023-30861)',
      'PyYAML 5.3.1 (CVE-2020-14343)',
      'Werkzeug 2.0.2 (CVE-2023-25577)',
      'Werkzeug 2.0.2 (CVE-2024-34069)',
      'setuptools 58.1.0 (CVE-2022-40897)'
    ],
    // Overview 및 Vulnerabilities 탭에서 사용
    vulnerabilities: [
      { cve: 'CVE-2020-14343', package: 'PyYAML', version: '5.3.1', severity: 'CRITICAL', directCall: '예 (config.py)' },
      { cve: 'CVE-2023-30861', package: 'Flask', version: '2.0.2', severity: 'HIGH', directCall: '아니요' },
      { cve: 'CVE-2023-25577', package: 'Werkzeug', version: '2.0.2', severity: 'HIGH', directCall: '예 (app.py)' },
      { cve: 'CVE-2024-34069', package: 'Werkzeug', version: '2.0.2', severity: 'HIGH', directCall: '아니요' },
      { cve: 'CVE-2023-46136', package: 'Werkzeug', version: '2.0.2', severity: 'MEDIUM', directCall: '아니요' },
      { cve: 'CVE-2024-49766', package: 'Werkzeug', version: '2.0.2', severity: 'MEDIUM', directCall: '아니요' },
      { cve: 'CVE-2024-49767', package: 'Werkzeug', version: '2.0.2', severity: 'MEDIUM', directCall: '아니요' },
      { cve: 'CVE-2023-23934', package: 'Werkzeug', version: '2.0.2', severity: 'LOW', directCall: '아니요' },
    ],
    // Vulnerabilities 탭 상단 요약용
    severitySummary: [
      { severity: 'CRITICAL', count: 1, description: '즉시 조치 필요' },
      { severity: 'HIGH', count: 6, description: '높은 위험도' },
      { severity: 'MEDIUM', count: 5, description: '권장 조치' },
      { severity: 'LOW', count: 1, description: '낮은 위험도' }
    ],
    // Libraries & APIs 탭용
    libraryMappings: [
      { library: 'PyYAML', version: '5.3.1', api: 'yaml.full_load', cve: 'CVE-2020-14343' },
      { library: 'Werkzeug', version: '2.0.2', api: 'werkzeug.serving.run_simple', cve: 'CVE-2023-25577' },
      { library: 'Flask', version: '2.0.2', api: 'unknown', cve: 'CVE-2023-30861' },
      { library: 'setuptools', version: '58.1.0', api: 'package_index.py', cve: 'CVE-2022-40897' }
    ],
    // Patch Priority 탭용
    patchPriority: [
      { id: 1, setNo: 1, library: 'PyYAML', version: '5.3.1', cves: 'CVE-2020-14343', score: 100, urgency: 'IMMEDIATE', description: 'PyYAML 5.4 업데이트 권장' },
      { id: 2, setNo: 2, library: 'Werkzeug', version: '2.0.2', cves: 'CVE-2023-25577 외 4건', score: 100, urgency: 'IMMEDIATE', description: 'Werkzeug 3.0.6 업데이트 권장' },
      { id: 3, setNo: 3, library: 'setuptools', version: '58.1.0', cves: 'CVE-2022-40897', score: 54, urgency: 'PLANNED', description: 'setuptools 65.5.1 업데이트 권장' },
      { id: 4, setNo: 4, library: 'Flask', version: '2.0.2', cves: 'CVE-2023-30861', score: 52, urgency: 'PLANNED', description: 'Flask 2.3.2 업데이트 권장' }
    ],
    // Logs 탭용
    logs: [
      { timestamp: '12:43:15', message: '이미지 분석 시작: pyyaml-vuln.tar' },
      { timestamp: '12:43:20', message: 'Docker 레이어 추출 완료 (/app)' },
      { timestamp: '12:43:45', message: 'Trivy 스캔 완료 (총 13개 취약점 탐지)' },
      { timestamp: '12:43:50', message: 'AST 정적 분석 완료 (직접 호출 경로 2개 식별)' },
      { timestamp: '12:44:00', message: '패치 우선순위 계산 완료' },
      { timestamp: '12:44:01', message: '분석 리포트 생성 완료' }
    ]
  };

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'vulns', label: 'Vulnerabilities' },
    { id: 'libs', label: 'Libraries & APIs' },
    { id: 'patch', label: 'Patch Priority' },
    { id: 'logs', label: 'Logs' }
  ];

  const renderTabContent = () => {
    switch(activeTab) {
      case 'overview':
        return (
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[400px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">주요 취약점 하이라이트</div>
            <div className="text-[11px] text-gray-600 mb-2">
              심각도가 높고 실제 코드 경로로 이어지는 취약점들을 우선적으로 정리했습니다.
            </div>

            <ul className="text-xs text-gray-900 ml-4 mb-3 leading-relaxed space-y-1">
              {sampleData.highlights.map((highlight, idx) => (
                <li key={idx}>{highlight}</li>
              ))}
            </ul>

            <hr className="border-t border-gray-200 my-2.5" />

            <div className="text-[13px] font-medium mb-2 text-gray-900">심각도별 취약점 테이블</div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-gray-100">
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">CVE</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">패키지</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">버전</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">심각도</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">직접 호출 여부</th>
                  </tr>
                </thead>
                <tbody>
                  {sampleData.vulnerabilities.map((vuln, idx) => (
                    <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                      <td className="px-2 py-2">{vuln.cve}</td>
                      <td className="px-2 py-2">{vuln.package}</td>
                      <td className="px-2 py-2">{vuln.version}</td>
                      <td className="px-2 py-2">
                        <RiskBadge level={vuln.severity} />
                      </td>
                      <td className="px-2 py-2">{vuln.directCall}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );

      case 'vulns':
        return (
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[400px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">Vulnerabilities</div>
            <div className="text-[11px] text-gray-600 mb-2">
              탐지된 모든 취약점의 상세 목록과 통계입니다.
            </div>

            <table className="w-full text-xs border-collapse mt-2 mb-3">
              <thead>
                <tr className="bg-gray-100">
                  <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">심각도</th>
                  <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">개수</th>
                  <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">설명</th>
                </tr>
              </thead>
              <tbody>
                {sampleData.severitySummary.map((item, idx) => (
                  <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                    <td className="px-2 py-2">
                      <RiskBadge level={item.severity} />
                    </td>
                    <td className="px-2 py-2">{item.count}</td>
                    <td className="px-2 py-2">{item.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <hr className="border-t border-gray-200 my-2.5" />

            <div className="text-[13px] font-medium mb-2 text-gray-900">전체 취약점 목록</div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-gray-100">
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">CVE</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">패키지</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">버전</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">심각도</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">직접 호출</th>
                  </tr>
                </thead>
                <tbody>
                  {sampleData.vulnerabilities.map((vuln, idx) => (
                    <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                      <td className="px-2 py-2">{vuln.cve}</td>
                      <td className="px-2 py-2">{vuln.package}</td>
                      <td className="px-2 py-2">{vuln.version}</td>
                      <td className="px-2 py-2">
                        <RiskBadge level={vuln.severity} />
                      </td>
                      <td className="px-2 py-2">{vuln.directCall}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );

      case 'libs':
        return (
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[400px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">Libraries &amp; APIs</div>
            <div className="text-[11px] text-gray-600 mb-2">
              어떤 라이브러리가 어떤 API를 통해 취약점과 연결되는지 정리한 뷰입니다.
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-gray-100">
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">라이브러리</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">버전</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">API</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">CVE</th>
                  </tr>
                </thead>
                <tbody>
                  {sampleData.libraryMappings.map((mapping, idx) => (
                    <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                      <td className="px-2 py-2">{mapping.library}</td>
                      <td className="px-2 py-2">{mapping.version}</td>
                      <td className="px-2 py-2">
                        <code className="bg-gray-100 px-1 py-0.5 rounded text-blue-700">{mapping.api}</code>
                      </td>
                      <td className="px-2 py-2 max-w-[150px] truncate" title={mapping.cve}>{mapping.cve}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );

      case 'patch':
        return (
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[400px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">Patch Priority</div>
            <div className="text-[11px] text-gray-600 mb-2">
              "지금 당장 해야 할 패치"를 세트 단위로 묶어 우선순위를 부여합니다.
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-gray-100">
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">세트</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">라이브러리</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">버전</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">CVEs</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">우선순위</th>
                    <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">점수</th>
                  </tr>
                </thead>
                <tbody>
                  {sampleData.patchPriority.map((patch) => (
                    <tr key={patch.id} className="border-b border-gray-200 hover:bg-gray-50">
                      <td className="px-2 py-2">#{patch.setNo}</td>
                      <td className="px-2 py-2">{patch.library}</td>
                      <td className="px-2 py-2">{patch.version}</td>
                      <td className="px-2 py-2 max-w-[150px] truncate" title={patch.cves}>{patch.cves}</td>
                      <td className="px-2 py-2">
                        <RiskBadge level={patch.urgency} />
                      </td>
                      <td className="px-2 py-2">{patch.score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );

      case 'logs':
        return (
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[400px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">Logs</div>
            <div className="text-[11px] text-gray-600 mb-2">
              분석 파이프라인 실행 로그를 시간 순서대로 정리한 영역입니다.
            </div>

            <ul className="text-xs text-gray-900 ml-4 leading-relaxed space-y-1 font-mono">
              {sampleData.logs.map((log, idx) => (
                <li key={idx}>
                  <span className="text-gray-400">[{log.timestamp}]</span> {log.message}
                </li>
              ))}
            </ul>
          </div>
        );
      
      default:
        return null;
    }
  };

  return (
    <main className="p-4 flex flex-col gap-4 bg-white overflow-y-auto h-full">
      <div className="flex justify-between items-start gap-4">
        <div>
          <div className="text-lg font-semibold text-gray-900">{sampleData.title}</div>
          <div className="text-xs text-gray-600 mt-1 flex gap-2 flex-wrap items-center">
            <span>이미지 태그: <code className="bg-gray-100 px-1 py-0.5 rounded text-blue-700">{sampleData.imageTag}</code></span>
            {sampleData.tags.map((tag, idx) => (
              <span key={idx} className="px-1.5 py-0.5 rounded-full border border-gray-200 text-[10px] text-gray-600 bg-gray-50">{tag}</span>
            ))}
          </div>

          <div className="mt-3 grid grid-cols-3 gap-2.5 text-xs">
            <div className="rounded-xl border border-gray-200 bg-gray-50 p-2.5">
              <div className="text-[11px] text-gray-600 mb-1">전체 리스크</div>
              <div className={`text-[15px] font-semibold ${
                  sampleData.summary.riskLevel === 'CRITICAL' ? 'text-red-600' : 'text-gray-900'
                }`}>
                {sampleData.summary.riskLevel}
              </div>
              <div className="text-[11px] text-gray-600 mt-0.5">
                Critical {sampleData.summary.criticalCount} · High {sampleData.summary.highCount} · Medium {sampleData.summary.mediumCount} · Low {sampleData.summary.lowCount}
              </div>
            </div>
            <div className="rounded-xl border border-gray-200 bg-gray-50 p-2.5">
              <div className="text-[11px] text-gray-600 mb-1">패치 우선순위 세트</div>
              <div className="text-[15px] font-semibold text-gray-900">{sampleData.summary.patchSets}개</div>
              <div className="text-[11px] text-gray-600 mt-0.5">{sampleData.summary.patchTargets}</div>
            </div>
            <div className="rounded-xl border border-gray-200 bg-gray-50 p-2.5">
              <div className="text-[11px] text-gray-600 mb-1">직접 호출 경로</div>
              <div className="text-[15px] font-semibold text-gray-900">{sampleData.summary.callPaths}개</div>
              <div className="text-[11px] text-gray-600 mt-0.5">RCE로 이어질 수 있는 코드 경로</div>
            </div>
          </div>
        </div>
      </div>

      <div className="mt-2 flex flex-col gap-2">
        <div className="inline-flex gap-1.5 p-0.5 rounded-full bg-gray-100 self-start">
          {tabs.map((tab) => (
            <TabButton
              key={tab.id}
              label={tab.label}
              isActive={activeTab === tab.id}
              onClick={() => setActiveTab(tab.id)}
            />
          ))}
        </div>

        {renderTabContent()}
      </div>

      <div className="text-[11px] text-gray-600 mt-1">
        * Analysis ID: ae36e75a0eb147838c4db562df173933
      </div>
    </main>
  );
};

export default SampleAnalysisPreviewPage;