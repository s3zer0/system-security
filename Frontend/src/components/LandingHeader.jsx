import React from 'react';
import { Link } from 'react-router-dom';

const NavLink = ({ to, children }) => (
  <Link 
    to={to} 
    className="text-sm text-gray-600 hover:text-gray-800 transition ml-4"
  >
    {children}
  </Link>
);

const LandingHeader = () => {
  return (
    <header className="landing-header h-16 flex items-center justify-between px-6 border-b border-gray-200 bg-white">
      
      {/* Logo: .landing-logo */}
      <Link to="/" className="landing-logo font-semibold tracking-wider flex items-center gap-2 cursor-pointer">
        <span className="inline-flex w-5 h-5 rounded-md bg-gradient-to-br from-blue-600 to-green-500"></span>
        <div className="text-gray-900">System-Security</div>
      </Link>

      {/* Navigation */}
      <nav>
        <NavLink to="/features">기능</NavLink>
        <NavLink to="/docs">문서</NavLink>
        <NavLink to="/github">GitHub</NavLink>
        <NavLink to="/login">
          <button className="text-sm text-gray-600 hover:text-gray-800 transition ml-4 bg-transparent border-none cursor-pointer">
            로그인
          </button>
        </NavLink>
      </nav>
    </header>
  );
};

export default LandingHeader;
