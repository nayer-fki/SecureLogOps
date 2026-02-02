import { Routes, Route, Navigate } from "react-router-dom";
import UploadTestPage from "./pages/UploadTestPage";
// import LoginPage from "./pages/LoginPage";  // إذا تحب تخليه موجود

export default function App() {
  return (
    <Routes>
      <Route path="/upload-test" element={<UploadTestPage />} />
      <Route path="*" element={<Navigate to="/upload-test" replace />} />
    </Routes>
  );
}
