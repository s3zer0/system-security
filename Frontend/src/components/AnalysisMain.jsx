import { useState } from 'react';
import TabButton from './TabButton';

// Helper function to transform backend data to frontend format
const transformData = (backendData) => {
  if (!backendData || !backendData.meta || !backendData.result) {
    return null;
  }

  const { meta, result } = backendData;
  const summary = result.vulnerabilities_summary || {};
  const vulnerabilities = result.vulnerabilities || [];
  const patchPriority = result.patch_priority || [];
  const logs = result.logs || [];

  // Transform vulnerabilities array
  const transformedVulnerabilities = vulnerabilities.map((vuln) => ({
    cve: vuln.cve_id,
    package: vuln.package,
    version: vuln.version || 'N/A',
    severity: vuln.severity,
    directCall: vuln.direct_call ? 'Yes' : 'No',
    evidence: vuln.call_evidence || 'N/A'
  }));

  // Transform patch priority array
  const transformedPatchPriority = patchPriority.map((patch) => ({
    id: patch.set_no,
    description: patch.note,
    packages: patch.packages || []
  }));

  // Transform logs array (backend returns array of strings)
  const transformedLogs = logs.map((logMessage, index) => ({
    timestamp: `Log ${index + 1}`,
    message: logMessage
  }));

  // Build summary with vulnerabilities_summary data
  const transformedSummary = {
    riskLevel: summary.overall_risk || 'Unknown',
    criticalCount: summary.critical || 0,
    highCount: summary.high || 0,
    mediumCount: summary.medium || 0,
    lowCount: summary.low || 0,
    patchSets: transformedPatchPriority.length,
    patchTargets: transformedPatchPriority.length > 0
      ? transformedPatchPriority.map(p => p.packages.join(', ')).join('; ')
      : 'N/A',
    callPaths: transformedVulnerabilities.filter(v => v.directCall === 'Yes').length
  };

  // Build severity summary for vulns tab
  const severitySummary = [
    {
      severity: 'Critical',
      count: summary.critical || 0,
      description: 'RCE 가능성 및 인증 우회 등 즉시 조치가 필요한 취약점'
    },
    {
      severity: 'High',
      count: summary.high || 0,
      description: '네트워크 노출 시 악용 가능성이 높은 취약점'
    },
    {
      severity: 'Medium',
      count: summary.medium || 0,
      description: '구버전 라이브러리, 정보 노출 등 장기적으로 패치가 필요한 이슈'
    },
    {
      severity: 'Low',
      count: summary.low || 0,
      description: '낮은 우선순위 취약점'
    }
  ];

  // Build highlights from critical/high vulnerabilities
  const highlights = transformedVulnerabilities
    .filter(v => v.severity === 'Critical' || v.severity === 'High')
    .slice(0, 5)
    .map(v => `${v.package} (${v.cve}) - ${v.severity} severity${v.directCall === 'Yes' ? ' - Direct call detected' : ''}`);

  return {
    title: meta.original_filename || meta.file_name || 'Analysis',
    imageTag: meta.analysis_id || 'N/A',
    tags: [], // Backend doesn't provide tags in new schema
    summary: transformedSummary,
    highlights: highlights.length > 0 ? highlights : ['No critical vulnerabilities detected'],
    vulnerabilities: transformedVulnerabilities,
    severitySummary,
    libraryMappings: [], // Not available in new schema, could be derived from vulnerabilities if needed
    patchPriority: transformedPatchPriority,
    logs: transformedLogs
  };
};

const AnalysisMain = ({ data }) => {
  const [activeTab, setActiveTab] = useState('overview');

  // Transform backend data or use default fallback
  const analysisData = data ? transformData(data) : {
    title: 'Python 기반 이미지 분석 요약',
    imageTag: 'pyyaml-app:2025-10-01',
    tags: ['Python', 'Ubuntu 22.04'],
    summary: {
      riskLevel: 'HIGH',
      criticalCount: 3,
      highCount: 4,
      mediumCount: 9,
      patchSets: 5,
      patchTargets: 'PyYAML, OpenSSL, Requests 중심',
      callPaths: 12
    },
    highlights: [
      'PyYAML 5.3.1의 full_load 사용으로 인한 RCE 가능성 (CVE-2020-14343)',
      'OpenSSL 구버전으로 인한 TLS 취약점 2건 (중요도 High)',
      'Requests 라이브러리의 인증 우회 관련 취약점 1건 (중요도 Medium)'
    ],
    vulnerabilities: [
      {
        cve: 'CVE-2020-14343',
        package: 'PyYAML',
        version: '5.3.1',
        severity: 'Critical',
        directCall: '예 (config_loader.py:42)'
      },
      {
        cve: 'CVE-2023-XYZ',
        package: 'OpenSSL',
        version: '1.1.1f',
        severity: 'High',
        directCall: '예 (tls_client.py:12)'
      },
      {
        cve: 'CVE-2022-ABC',
        package: 'requests',
        version: '2.23.0',
        severity: 'Medium',
        directCall: '아니요'
      }
    ],
    severitySummary: [
      {
        severity: 'Critical',
        count: 3,
        description: 'RCE 가능성 및 인증 우회 등 즉시 조치가 필요한 취약점'
      },
      {
        severity: 'High',
        count: 4,
        description: '네트워크 노출 시 악용 가능성이 높은 취약점'
      },
      {
        severity: 'Medium',
        count: 9,
        description: '구버전 라이브러리, 정보 노출 등 장기적으로 패치가 필요한 이슈'
      }
    ],
    libraryMappings: [
      {
        library: 'PyYAML',
        version: '5.3.1',
        api: 'yaml.full_load',
        cve: 'CVE-2020-14343'
      },
      {
        library: 'OpenSSL',
        version: '1.1.1f',
        api: 'TLS 핸드셰이크 구현',
        cve: 'CVE-2023-XYZ'
      },
      {
        library: 'requests',
        version: '2.23.0',
        api: '인증 우회 관련 옵션 조합',
        cve: 'CVE-2022-ABC'
      }
    ],
    patchPriority: [
      {
        id: 1,
        description: 'PyYAML 6.0 이상으로 업그레이드 및 safe_load로 교체'
      },
      {
        id: 2,
        description: 'OpenSSL 3.x로 업그레이드 및 취약한 CipherSuite 비활성화'
      },
      {
        id: 3,
        description: 'requests 최신 버전으로 업데이트 및 인증 관련 옵션 재검토'
      }
    ],
    logs: [
      { timestamp: '21:30:02', message: '이미지 업로드 완료 · pyyaml-app.tar' },
      { timestamp: '21:30:05', message: 'Trivy scan 시작' },
      { timestamp: '21:30:09', message: 'Trivy 결과 파싱 완료 · Critical 3, High 4, Medium 9' },
      { timestamp: '21:30:15', message: '라이브러리 & API 매핑 완료' },
      { timestamp: '21:30:22', message: 'AST 분석 완료 · RCE 경로 2개 탐지' },
      { timestamp: '21:30:30', message: '패치 우선순위 리포트 생성 완료' }
    ]
  };

  // 탭 목록
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
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[350px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">주요 취약점 하이라이트</div>
            <div className="text-[11px] text-gray-600 mb-2">
              심각도가 높고 실제 코드 경로로 이어지는 취약점들을 우선적으로 정리했습니다.
            </div>

            <ul className="text-xs text-gray-900 ml-4 mb-3 leading-relaxed space-y-1">
              {analysisData.highlights.map((highlight, idx) => (
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
                  {analysisData.vulnerabilities.map((vuln, idx) => (
                    <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                      <td className="px-2 py-2">{vuln.cve}</td>
                      <td className="px-2 py-2">{vuln.package}</td>
                      <td className="px-2 py-2">{vuln.version}</td>
                      <td className="px-2 py-2">{vuln.severity}</td>
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
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[350px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">Vulnerabilities</div>
            <div className="text-[11px] text-gray-600 mb-2">
              Trivy 스캔 결과를 기반으로 심각도, 패키지, 버전별로 정리된 상세 목록입니다.
            </div>

            <table className="w-full text-xs border-collapse mt-2">
              <thead>
                <tr className="bg-gray-100">
                  <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">심각도</th>
                  <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">개수</th>
                  <th className="text-left px-2 py-2 text-[11px] text-gray-600 font-medium">설명</th>
                </tr>
              </thead>
              <tbody>
                {analysisData.severitySummary.map((item, idx) => (
                  <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                    <td className="px-2 py-2">{item.severity}</td>
                    <td className="px-2 py-2">{item.count}</td>
                    <td className="px-2 py-2">{item.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );

      case 'libs':
        return (
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[350px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">Libraries &amp; APIs</div>
            <div className="text-[11px] text-gray-600 mb-2">
              어떤 라이브러리가 어떤 API를 통해 취약점과 연결되는지 정리한 뷰입니다.
            </div>

            {analysisData.libraryMappings && analysisData.libraryMappings.length > 0 ? (
              <ul className="text-xs text-gray-900 ml-4 leading-relaxed space-y-1">
                {analysisData.libraryMappings.map((mapping, idx) => (
                  <li key={idx}>
                    {mapping.library} {mapping.version} · <code className="bg-gray-100 px-1 py-0.5 rounded text-blue-700">{mapping.api}</code> · {mapping.cve}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-xs text-gray-600 ml-4">
                Library mapping data not available in current schema.
              </div>
            )}
          </div>
        );

      case 'patch':
        return (
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[350px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">Patch Priority</div>
            <div className="text-[11px] text-gray-600 mb-2">
              "지금 당장 해야 할 패치"를 세트 단위로 묶어 우선순위를 부여합니다.
            </div>

            <ul className="text-xs text-gray-900 ml-4 leading-relaxed space-y-1">
              {analysisData.patchPriority.map((patch) => (
                <li key={patch.id}>
                  [세트 #{patch.id}] {patch.description}
                  {patch.packages && patch.packages.length > 0 && (
                    <span className="text-gray-600"> - {patch.packages.join(', ')}</span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        );

      case 'logs':
        return (
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[350px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">Logs</div>
            <div className="text-[11px] text-gray-600 mb-2">
              분석 파이프라인 실행 로그를 시간 순서대로 정리한 영역입니다.
            </div>

            <ul className="text-xs text-gray-900 ml-4 leading-relaxed space-y-1">
              {analysisData.logs.map((log, idx) => (
                <li key={idx}>
                  [{log.timestamp}] {log.message}
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
    <main className="p-4 flex flex-col gap-4 bg-white overflow-y-auto">
      <div className="flex justify-between items-start gap-4">
        <div>
          <div className="text-lg font-semibold text-gray-900">{analysisData.title}</div>
          <div className="text-xs text-gray-600 mt-1 flex gap-2 flex-wrap items-center">
            <span>이미지 태그: <code className="bg-gray-100 px-1 py-0.5 rounded text-blue-700">{analysisData.imageTag}</code></span>
            {analysisData.tags && analysisData.tags.map((tag, idx) => (
              <span key={idx} className="px-1.5 py-0.5 rounded-full border border-gray-200 text-[10px] text-gray-600 bg-gray-50">{tag}</span>
            ))}
          </div>

          <div className="mt-3 grid grid-cols-3 gap-2.5 text-xs">
            <div className="rounded-xl border border-gray-200 bg-gray-50 p-2.5">
              <div className="text-[11px] text-gray-600 mb-1">전체 리스크</div>
              <div className="text-[15px] font-semibold text-gray-900">{analysisData.summary.riskLevel}</div>
              <div className="text-[11px] text-gray-600 mt-0.5">
                Critical {analysisData.summary.criticalCount} · High {analysisData.summary.highCount} · Medium {analysisData.summary.mediumCount}
              </div>
            </div>
            <div className="rounded-xl border border-gray-200 bg-gray-50 p-2.5">
              <div className="text-[11px] text-gray-600 mb-1">패치 우선순위 세트</div>
              <div className="text-[15px] font-semibold text-gray-900">{analysisData.summary.patchSets}개</div>
              <div className="text-[11px] text-gray-600 mt-0.5">{analysisData.summary.patchTargets}</div>
            </div>
            <div className="rounded-xl border border-gray-200 bg-gray-50 p-2.5">
              <div className="text-[11px] text-gray-600 mb-1">직접 호출 경로</div>
              <div className="text-[15px] font-semibold text-gray-900">{analysisData.summary.callPaths}개</div>
              <div className="text-[11px] text-gray-600 mt-0.5">RCE로 이어질 수 있는 코드 경로</div>
            </div>
          </div>
        </div>
      </div>

      <div className="mt-2 flex flex-col gap-2">
        {/* TabButton 컴포넌트 사용 */}
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
        * 실제 구현 시에는 탭별로 별도의 API/데이터를 연결할 수 있습니다.
      </div>
    </main>
  );
};

export default AnalysisMain;
