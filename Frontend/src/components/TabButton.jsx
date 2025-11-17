// TabButton.jsx - 탭 버튼 공통 컴포넌트

export default function TabButton({ label, isActive, onClick }) {
  return (
    <button
      className={`px-2.5 py-1.5 rounded-full text-[11px] transition ${
        isActive
          ? 'bg-blue-50 border border-blue-600 text-blue-700 font-medium'
          : 'border border-transparent text-gray-600 hover:bg-gray-50'
      }`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}


