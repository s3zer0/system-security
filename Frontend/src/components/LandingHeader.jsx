// src/components/LandingHeader.jsx

import React from 'react';
import { Link } from 'react-router-dom';

const NavLink = ({ to, children }) => (
  <Link 
    to={to} 
    className="text-sm text-gray-600 hover:text-gray-800 transition ml-4 font-medium"
  >
    {children}
  </Link>
);

const LandingHeader = () => {
  const GITHUB_URL = "https://github.com/s3zer0/system-security";
  
  return (
    <header className="landing-header h-16 flex items-center justify-between px-6 border-b border-gray-200 bg-white">
      
      {/* Logo: font-bold 적용 */}
      <Link to="/" className="landing-logo font-bold tracking-wider flex items-center gap-2 cursor-pointer">
        <span className="inline-flex w-5 h-5 rounded-md bg-gradient-to-br from-blue-600 to-green-500"></span>
        <div className="text-gray-900">System-Security</div>
      </Link>

      {/* Navigation: font-medium 적용 */}
      <nav>
        <NavLink to="/features">기능</NavLink>
        <NavLink to="/docs">문서</NavLink>
        
        <a 
          href={GITHUB_URL}
          target="_blank" 
          rel="noopener noreferrer" 
          className="text-sm text-gray-600 hover:text-gray-800 transition ml-4 font-medium"
        >
          GitHub
        </a>
        
        <NavLink to="/login">
          <button className="text-sm text-gray-600 hover:text-gray-800 transition ml-4 bg-transparent border-none cursor-pointer font-medium">
            로그인
          </button>
        </NavLink>
      </nav>
    </header>
  );
};

export default LandingHeader;
