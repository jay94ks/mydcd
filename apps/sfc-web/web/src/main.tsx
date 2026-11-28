// SPDX-License-Identifier: Apache-2.0

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import { AuthProvider } from './auth/session';
import { ToastProvider } from './components/Toast';
import { App } from './App';
import './styles.css';
import { applyStoredTheme } from './lib/uiPrefs';

applyStoredTheme();

// 데이터 라우터: 화면 안의 <Routes>는 그대로 두고, useBlocker(나가기 확인)를 쓰려고 바깥만 바꾼다.
const router = createBrowserRouter([
  {
    path: '*',
    element: (
      <AuthProvider>
        <ToastProvider>
          <App />
        </ToastProvider>
      </AuthProvider>
    ),
  },
]);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
