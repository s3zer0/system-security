import { useState, useEffect } from 'react';
import TabButton from './TabButton';

const AnalysisMain = ({ analysisId }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [analysisData, setAnalysisData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchAnalysisData = async () => {
      if (!analysisId) {
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const response = await fetch(`/api/analysis/${analysisId}`);

        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") === -1) {
          throw new Error("서버 응답이 JSON이 아닙니다. (Proxy 설정을 확인하세요)");
        }

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        const { result, meta } = data;

        // Transform backend data to frontend format
        const transformedData = {
          title: `${result.language || 'Unknown'} 기반 이미지 분석 요약`,
          imageTag: meta.file_name || meta.input_file || 'unknown',
          tags: [result.language || 'Unknown', meta.created_at ? new Date(meta.created_at).toLocaleDateString() : ''],

          summary: {
            riskLevel: result.vulnerabilities_summary?.overall_risk || 'UNKNOWN',
            criticalCount: result.vulnerabilities_summary?.critical ?? result.vulnerabilities_summary?.critical_count ?? 0,
            highCount: result.vulnerabilities_summary?.high ?? result.vulnerabilities_summary?.high_count ?? 0,
            mediumCount: result.vulnerabilities_summary?.medium ?? result.vulnerabilities_summary?.medium_count ?? 0,
            lowCount: result.vulnerabilities_summary?.low ?? result.vulnerabilities_summary?.low_count ?? 0,
            patchSets: result.patch_priority?.length || 0,
            patchTargets: result.patch_priority?.slice(0, 3).map(p => p.package).join(', ') || 'N/A',
            callPaths: result.vulnerabilities?.filter(v => v.direct_call).length || 0
          },

          highlights: result.vulnerabilities
            ?.filter(v => ['CRITICAL', 'HIGH'].includes((v.severity || '').toUpperCase()))
            .slice(0, 5)
            .map(v => `${v.package} ${v.version} (${v.cve_id})`) || [],

          vulnerabilities: result.vulnerabilities?.map(v => ({
            cve: v.cve_id || 'N/A',
            package: v.package || 'Unknown',
            version: v.version || 'N/A',
            severity: (v.severity || 'Unknown').toUpperCase(),
            directCall: v.direct_call ? '예' : '아니요',
            title: v.description ? v.description.substring(0, 50) + '...' : ''
          })) || [],

          severitySummary: [
            { severity: 'Critical', count: result.vulnerabilities_summary?.critical ?? 0, description: '즉시 조치 필요' },
            { severity: 'High', count: result.vulnerabilities_summary?.high ?? 0, description: '높은 위험도' },
            { severity: 'Medium', count: result.vulnerabilities_summary?.medium ?? 0, description: '권장 조치' },
            { severity: 'Low', count: result.vulnerabilities_summary?.low ?? 0, description: '낮은 위험도' }
          ].filter(s => s.count > 0),

          libraryMappings: result.libraries_and_apis?.map(item => ({
            library: item.package,
            version: item.version,
            api: `${item.module}.${item.api}`,
            cve: item.related_cves?.join(', ') || '-'
          })) || [],

          patchPriority: result.patch_priority?.map((patch) => ({
            id: patch.set_no,
            setNo: patch.set_no,
            library: patch.package,
            version: patch.current_version,
            cves: 'N/A',
            score: patch.score,
            urgency: patch.urgency,
            description: `${patch.package} ${patch.recommended_version || ''} 업데이트 권장`
          })) || [],

          logs: result.logs?.map(log => ({
            timestamp: new Date(log.timestamp || Date.now()).toLocaleTimeString(),
            message: log.message || ''
          })) || []
        };

        setAnalysisData(transformedData);
      } catch (err) {
        console.error('Analysis data fetch error:', err);
        setError(err.message || '분석 데이터를 불러오는데 실패했습니다.');
      } finally {
        setLoading(false);
      }
    };

    fetchAnalysisData();
  }, [analysisId]);

  if (loading) {
    return (
      <main className="p-4 flex items-center justify-center min-h-screen bg-white">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <div className="text-sm text-gray-600">분석 데이터를 불러오는 중...</div>
        </div>
      </main>
    );
  }

  if (error) {
    return (
      <main className="p-4 flex items-center justify-center min-h-screen bg-white">
        <div className="text-center">
          <div className="text-red-600 text-lg mb-2">⚠️ 오류 발생</div>
          <div className="text-sm text-gray-600">{error}</div>
          <div className="text-xs text-gray-400 mt-2">ID: {analysisId || '없음'}</div>
        </div>
      </main>
    );
  }

  if (!analysisData) {
    return (
      <main className="p-4 flex items-center justify-center min-h-screen bg-white">
        <div className="text-sm text-gray-600">분석 데이터가 없습니다.</div>
      </main>
    );
  }

  // 탭 목록
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'vulns', label: 'Vulnerabilities' },
    { id: 'libs', label: 'Libraries & APIs' },
    { id: 'patch', label: 'Patch Priority' },
    { id: 'logs', label: 'Logs' }
  ];

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[350px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">주요 취약점 하이라이트</div>
            <div className="text-[11px] text-gray-600 mb-2">
              심각도가 높고 실제 코드 경로로 이어지는 취약점들을 우선적으로 정리했습니다.
            </div>

            {analysisData.highlights.length > 0 ? (
              <ul className="text-xs text-gray-900 ml-4 mb-3 leading-relaxed space-y-1">
                {analysisData.highlights.map((highlight, idx) => (
                  <li key={idx}>{highlight}</li>
                ))}
              </ul>
            ) : (
              <div className="text-[11px] text-gray-600 mb-3">Critical 또는 High 취약점이 없습니다.</div>
            )}

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
                  {analysisData.vulnerabilities.slice(0, 10).map((vuln, idx) => (
                    <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                      <td className="px-2 py-2">{vuln.cve}</td>
                      <td className="px-2 py-2">{vuln.package}</td>
                      <td className="px-2 py-2">{vuln.version}</td>
                      <td className="px-2 py-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${vuln.severity === 'Critical' || vuln.severity === 'CRITICAL' ? 'bg-red-100 text-red-700' :
                            vuln.severity === 'High' || vuln.severity === 'HIGH' ? 'bg-orange-100 text-orange-700' :
                              vuln.severity === 'Medium' ? 'bg-yellow-100 text-yellow-700' :
                                'bg-gray-100 text-gray-700'
                          }`}>
                          {vuln.severity}
                        </span>
                      </td>
                      <td className="px-2 py-2">{vuln.directCall}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {analysisData.vulnerabilities.length > 10 && (
              <div className="text-[11px] text-gray-600 mt-2 text-center">
                ...외 {analysisData.vulnerabilities.length - 10}개 취약점
              </div>
            )}
          </div>
        );

      case 'vulns':
        return (
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[350px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">Vulnerabilities</div>
            <div className="text-[11px] text-gray-600 mb-2">
              Trivy 스캔 결과를 기반으로 심각도, 패키지, 버전별로 정리된 상세 목록입니다.
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
                {analysisData.severitySummary.map((item, idx) => (
                  <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                    <td className="px-2 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${item.severity === 'Critical' ? 'bg-red-100 text-red-700' :
                          item.severity === 'High' ? 'bg-orange-100 text-orange-700' :
                            item.severity === 'Medium' ? 'bg-yellow-100 text-yellow-700' :
                              'bg-gray-100 text-gray-700'
                        }`}>
                        {item.severity}
                      </span>
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
                  {analysisData.vulnerabilities.map((vuln, idx) => (
                    <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                      <td className="px-2 py-2">{vuln.cve}</td>
                      <td className="px-2 py-2">{vuln.package}</td>
                      <td className="px-2 py-2">{vuln.version}</td>
                      <td className="px-2 py-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${vuln.severity === 'Critical' || vuln.severity === 'CRITICAL' ? 'bg-red-100 text-red-700' :
                            vuln.severity === 'High' || vuln.severity === 'HIGH' ? 'bg-orange-100 text-orange-700' :
                              vuln.severity === 'Medium' ? 'bg-yellow-100 text-yellow-700' :
                                'bg-gray-100 text-gray-700'
                          }`}>
                          {vuln.severity}
                        </span>
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
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[350px] overflow-auto">
            <div className="text-[13px] font-medium mb-1.5 text-gray-900">Libraries &amp; APIs</div>
            <div className="text-[11px] text-gray-600 mb-2">
              어떤 라이브러리가 어떤 API를 통해 취약점과 연결되는지 정리한 뷰입니다.
            </div>

<<<<<<< HEAD
        {
          analysisData.libraryMappings && analysisData.libraryMappings.length > 0 ? (
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
=======
            {analysisData.libraryMappings.length > 0 ? (
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
                    {analysisData.libraryMappings.slice(0, 20).map((mapping, idx) => (
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
                {analysisData.libraryMappings.length > 20 && (
                  <div className="text-[11px] text-gray-600 mt-2 text-center">
                    ...외 {analysisData.libraryMappings.length - 20}개 매핑
                  </div>
                )}
              </div>
            ) : (
              <div className="text-[11px] text-gray-600">라이브러리-API 매핑 데이터가 없습니다.</div>
>>>>>>> origin/main
        )
        }
          </div >
        );

      case 'patch':
return (
  <div className="rounded-xl border border-gray-200 bg-gray-50 p-3 text-xs max-h-[350px] overflow-auto">
    <div className="text-[13px] font-medium mb-1.5 text-gray-900">Patch Priority</div>
    <div className="text-[11px] text-gray-600 mb-2">
      "지금 당장 해야 할 패치"를 세트 단위로 묶어 우선순위를 부여합니다.
    </div>

<<<<<<< HEAD
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
=======
            {analysisData.patchPriority.length > 0 ? (
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
                    {analysisData.patchPriority.map((patch) => (
                      <tr key={patch.id} className="border-b border-gray-200 hover:bg-gray-50">
                        <td className="px-2 py-2">#{patch.setNo}</td>
                        <td className="px-2 py-2">{patch.library}</td>
                        <td className="px-2 py-2">{patch.version}</td>
                        <td className="px-2 py-2 max-w-[150px] truncate" title={patch.cves}>{patch.cves}</td>
                        <td className="px-2 py-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                            patch.urgency === 'Critical' ? 'bg-red-100 text-red-700' :
                            patch.urgency === 'High' ? 'bg-orange-100 text-orange-700' :
                            patch.urgency === 'Medium' ? 'bg-yellow-100 text-yellow-700' :
                            'bg-gray-100 text-gray-700'
                          }`}>
                            {patch.urgency}
                          </span>
                        </td>
                        <td className="px-2 py-2">{patch.score}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-[11px] text-gray-600">패치 우선순위 데이터가 없습니다.</div>
            )}
>>>>>>> origin/main
          </div >
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
            <div className={`text-[15px] font-semibold ${analysisData.summary.riskLevel === 'CRITICAL' ? 'text-red-600' :
                analysisData.summary.riskLevel === 'HIGH' ? 'text-orange-600' :
                  'text-gray-900'
              }`}>
              {analysisData.summary.riskLevel}
            </div>
            <div className="text-[11px] text-gray-600 mt-0.5">
              Critical {analysisData.summary.criticalCount} · High {analysisData.summary.highCount} · Medium {analysisData.summary.mediumCount}
              {analysisData.summary.lowCount > 0 && ` · Low ${analysisData.summary.lowCount}`}
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
      * Analysis ID: {analysisId}
    </div>
  </main>
);
};

export default AnalysisMain;